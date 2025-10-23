/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 *
 */

package device_manager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"

	"kubevirt.io/client-go/log"

	"kubevirt.io/kubevirt/pkg/safepath"
	"kubevirt.io/kubevirt/pkg/util"
	pluginapi "kubevirt.io/kubevirt/pkg/virt-handler/device-manager/deviceplugin/v1beta1"
	"kubevirt.io/kubevirt/pkg/virt-handler/selinux"
)

const (
	qgsSocketDir  = "/var/run/tdx-qgs"
	qgsSocketName = "qgs.socket"
)

type QGSDevicePlugin struct {
	*DevicePluginBase
	socketDir   string
	socketName  string
	executor    selinux.Executor
	permManager PermissionManager
}

func (dpi *QGSDevicePlugin) Start(stop <-chan struct{}) (err error) {
	logger := log.DefaultLogger()
	dpi.stop = stop

	err = dpi.cleanup()
	if err != nil {
		return err
	}

	sock, err := net.Listen("unix", dpi.socketPath)
	if err != nil {
		return fmt.Errorf("error creating GRPC server socket: %v", err)
	}

	dpi.server = grpc.NewServer([]grpc.ServerOption{}...)
	defer dpi.stopDevicePlugin()

	pluginapi.RegisterDevicePluginServer(dpi.server, dpi)

	errChan := make(chan error, 2)

	go func() {
		errChan <- dpi.server.Serve(sock)
	}()

	err = waitForGRPCServer(dpi.socketPath, connectionTimeout)
	if err != nil {
		return fmt.Errorf("error starting the GRPC server: %v", err)
	}

	err = dpi.register()
	if err != nil {
		return fmt.Errorf("error registering with device plugin manager: %v", err)
	}

	go func() {
		errChan <- dpi.healthCheck()
	}()

	dpi.setInitialized(true)
	logger.Infof("%s device plugin started", dpi.resourceName)
	err = <-errChan

	return err
}

// ListAndWatch returns a stream of devices and their health status.
// Since all QGS device plugin devices represent the same underlying socket,
// health changes apply to all devices simultaneously.
func (dpi *QGSDevicePlugin) ListAndWatch(_ *pluginapi.Empty, s pluginapi.DevicePlugin_ListAndWatchServer) error {
	s.Send(&pluginapi.ListAndWatchResponse{Devices: dpi.devs})

	done := false
	for {
		select {
		case devHealth := <-dpi.health:
			// All QGS devices represent the same socket, so update all devices
			for _, dev := range dpi.devs {
				dev.Health = devHealth.Health
			}
			s.Send(&pluginapi.ListAndWatchResponse{Devices: dpi.devs})
		case <-dpi.stop:
			done = true
		case <-dpi.done:
			done = true
		}
		if done {
			break
		}
	}
	// Send empty list to increase the chance that kubelet acts fast on stopped device plugins
	emptyList := []*pluginapi.Device{}
	if err := s.Send(&pluginapi.ListAndWatchResponse{Devices: emptyList}); err != nil {
		log.DefaultLogger().Reason(err).Infof("%s device plugin failed to deregister", dpi.deviceName)
	}
	close(dpi.deregistered)
	return nil
}

func (dpi *QGSDevicePlugin) setSocketPermissions() error {
	qgsSock, err := safepath.JoinAndResolveWithRelativeRoot(util.HostRootMount, dpi.socketDir, dpi.socketName)
	if err != nil {
		return fmt.Errorf("error opening the QGS socket %s/%s: %v", dpi.socketDir, dpi.socketName, err)
	}
	err = dpi.permManager.ChownAtNoFollow(qgsSock, util.NonRootUID, util.NonRootUID)
	if err != nil {
		return fmt.Errorf("error setting the permission on QGS socket %s/%s: %v", dpi.socketDir, dpi.socketName, err)
	}
	if se, exists, err := dpi.executor.NewSELinux(); err == nil && exists {
		if err := selinux.RelabelFilesUnprivileged(se.IsPermissive(), qgsSock); err != nil {
			return fmt.Errorf("error relabeling QGS socket: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to detect the presence of selinux: %v", err)
	}

	return nil
}

func (dpi *QGSDevicePlugin) setSocketDirectoryPermissions() error {
	dir, err := safepath.JoinAndResolveWithRelativeRoot(util.HostRootMount, dpi.socketDir)
	if err != nil {
		return fmt.Errorf("error opening the QGS socket directory %s: %v", dpi.socketDir, err)
	}
	err = dpi.permManager.ChownAtNoFollow(dir, util.NonRootUID, util.NonRootUID)
	if err != nil {
		return fmt.Errorf("error setting the permission on QGS socket directory %s: %v", dpi.socketDir, err)
	}
	if se, exists, err := dpi.executor.NewSELinux(); err == nil && exists {
		if err := selinux.RelabelFilesUnprivileged(se.IsPermissive(), dir); err != nil {
			return fmt.Errorf("error relabeling QGS socket directory: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to detect the presence of selinux: %v", err)
	}

	return nil
}

func NewQGSDevicePlugin(maxDevices int) *QGSDevicePlugin {
	resourceName := "qgs"
	dpi := &QGSDevicePlugin{
		DevicePluginBase: &DevicePluginBase{
			health:       make(chan deviceHealth),
			resourceName: fmt.Sprintf("%s/%s", DeviceNamespace, resourceName),
			initialized:  false,
			lock:         &sync.Mutex{},
			done:         make(chan struct{}),
			deregistered: make(chan struct{}),
			socketPath:   SocketPath(resourceName),
			deviceName:   resourceName,
		},
		socketDir:   qgsSocketDir,
		socketName:  qgsSocketName,
		executor:    selinux.SELinuxExecutor{},
		permManager: NewPermissionManager(),
	}

	for i := 0; i < maxDevices; i++ {
		deviceId := resourceName + strconv.Itoa(i)
		dpi.devs = append(dpi.devs, &pluginapi.Device{
			ID:     deviceId,
			Health: pluginapi.Healthy,
		})
	}

	return dpi
}

// Register registers the device plugin for the given resourceName with Kubelet.
func (dpi *QGSDevicePlugin) register() error {
	conn, err := gRPCConnect(pluginapi.KubeletSocket, connectionTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pluginapi.NewRegistrationClient(conn)
	reqt := &pluginapi.RegisterRequest{
		Version:      pluginapi.Version,
		Endpoint:     path.Base(dpi.socketPath),
		ResourceName: dpi.resourceName,
	}

	_, err = client.Register(context.Background(), reqt)
	if err != nil {
		return err
	}
	return nil
}

func (dpi *QGSDevicePlugin) ensurePermissions() {
	logger := log.DefaultLogger()

	// Set directory permissions first
	if err := dpi.setSocketDirectoryPermissions(); err != nil {
		logger.Reason(err).Warningf("Failed to set QGS socket directory permissions")
	} else {
		logger.Infof("Successfully set permissions on QGS socket directory %s", dpi.socketDir)
	}

	// Then set socket permissions
	if err := dpi.setSocketPermissions(); err != nil {
		logger.Reason(err).Warningf("Failed to set QGS socket permissions")
	} else {
		logger.Infof("Successfully set permissions on QGS socket %s/%s", dpi.socketDir, dpi.socketName)
	}
}

// checkSocketAccessible verifies if the qemu user can access the socket
func (dpi *QGSDevicePlugin) checkSocketAccessible() bool {
	qgsSock, err := safepath.JoinAndResolveWithRelativeRoot(util.HostRootMount, dpi.socketDir, dpi.socketName)
	if err != nil {
		log.DefaultLogger().Reason(err).Warningf("error opening the QGS socket path %s/%s", dpi.socketDir, dpi.socketName)
		return false
	}

	// Check if qemu user (util.NonRootUID) can access the socket
	accessible, err := dpi.permManager.IsAccessibleByUser(qgsSock, util.NonRootUID)
	if err != nil {
		log.DefaultLogger().Reason(err).Warningf("error checking accessibility of QGS socket %s/%s", dpi.socketDir, dpi.socketName)
		return false
	}

	return accessible
}

func (dpi *QGSDevicePlugin) Allocate(ctx context.Context, r *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	log.DefaultLogger().Infof("QGS Allocate: resourceName: %s", dpi.deviceName)
	log.DefaultLogger().Infof("QGS Allocate: request: %v", r.ContainerRequests)
	response := pluginapi.AllocateResponse{}
	containerResponse := new(pluginapi.ContainerAllocateResponse)

	m := new(pluginapi.Mount)
	m.HostPath = dpi.socketDir
	m.ContainerPath = dpi.socketDir
	m.ReadOnly = false
	containerResponse.Mounts = []*pluginapi.Mount{m}

	response.ContainerResponses = []*pluginapi.ContainerAllocateResponse{containerResponse}

	return &response, nil
}

func (dpi *QGSDevicePlugin) healthCheck() error {
	logger := log.DefaultLogger()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to creating a fsnotify watcher: %v", err)
	}
	defer watcher.Close()

	// Access the socket via the host root mount since virt-handler runs in a container
	// This way we don't have to mount /var/run/tdx-qgs from the node
	devicePath := filepath.Join(util.HostRootMount, dpi.socketDir, dpi.socketName)

	// Start watching the directory before we check for socket existence to avoid races
	hostSocketDir := filepath.Join(util.HostRootMount, dpi.socketDir)
	err = watcher.Add(hostSocketDir)
	if err != nil {
		// If the directory doesn't exist, create a watcher on its parent
		parentDir := filepath.Dir(hostSocketDir)
		err = watcher.Add(parentDir)
		if err != nil {
			return fmt.Errorf("failed to add the socket parent directory to the watcher: %v", err)
		}
		logger.Warningf("directory '%s' is not present, waiting for it to be created", dpi.socketDir)
	}

	// Check initial state of the socket
	_, err = os.Stat(devicePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("could not stat the socket: %v", err)
		}
		logger.Warningf("socket '%s' is not present, the device plugin will mark devices as unhealthy", devicePath)
		// Mark all devices as unhealthy since socket doesn't exist
		// Send single health update since all devices represent the same socket
		dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
	} else {
		logger.Infof("socket '%s' is present.", devicePath)
		// Socket exists, check if qemu can access it
		if !dpi.checkSocketAccessible() {
			logger.Infof("socket is not accessible to qemu user, setting permissions")
			dpi.ensurePermissions()
		} else {
			logger.Infof("socket is already accessible to qemu user")
		}
	}

	// Watch the device plugin socket directory
	dirName := filepath.Dir(dpi.socketPath)
	err = watcher.Add(dirName)

	if err != nil {
		return fmt.Errorf("failed to add the device-plugin kubelet path to the watcher: %v", err)
	}
	_, err = os.Stat(dpi.socketPath)
	if err != nil {
		return fmt.Errorf("failed to stat the device-plugin socket: %v", err)
	}

	for {
		select {
		case <-dpi.stop:
			return nil
		case err := <-watcher.Errors:
			logger.Reason(err).Errorf("error watching devices and device plugin directory")
		case event := <-watcher.Events:
			logger.V(4).Infof("health Event: %v", event)

			// Check if the socket directory was created
			if event.Name == hostSocketDir && event.Op == fsnotify.Create {
				logger.Infof("QGS socket directory %s was created, adding watcher", hostSocketDir)
				err = watcher.Add(hostSocketDir)
				if err != nil {
					logger.Reason(err).Errorf("failed to add socket directory to watcher after creation")
				}
			}

			if event.Name == devicePath {
				// Health in this case is if the socket path actually exists
				if event.Op == fsnotify.Create {
					logger.Infof("monitored socket %s appeared", dpi.deviceName)
					// Socket was created, check if qemu can access it
					if !dpi.checkSocketAccessible() {
						logger.Infof("socket is not accessible to qemu user, setting permissions")
						dpi.ensurePermissions()
					} else {
						logger.Infof("socket is already accessible to qemu user")
					}
					// Mark all devices as healthy with single update
					// All devices represent the same socket
					dpi.health <- deviceHealth{Health: pluginapi.Healthy}
				} else if (event.Op == fsnotify.Remove) || (event.Op == fsnotify.Rename) {
					logger.Infof("monitored socket %s disappeared", dpi.deviceName)
					// Mark all devices as unhealthy with single update
					// All devices represent the same socket
					dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
				} else if event.Op == fsnotify.Chmod {
					logger.Infof("monitored socket %s had permissions/ownership changed, checking accessibility", dpi.deviceName)
					// Check if qemu user can still access the socket
					accessible := dpi.checkSocketAccessible()
					if accessible {
						logger.Infof("QGS socket %s is accessible to qemu user", dpi.deviceName)
						dpi.health <- deviceHealth{Health: pluginapi.Healthy}
					} else {
						logger.Warningf("QGS socket %s is NOT accessible to qemu user, fixing permissions", dpi.deviceName)
						dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
						dpi.ensurePermissions()
					}
				}
			} else if event.Name == dpi.socketPath && event.Op == fsnotify.Remove {
				logger.Infof("device plugin socket file for device %s was removed, kubelet probably restarted.", dpi.deviceName)
				return nil
			}
		}
	}
}
