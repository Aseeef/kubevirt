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
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"

	"kubevirt.io/client-go/log"

	"kubevirt.io/kubevirt/pkg/safepath"
	"kubevirt.io/kubevirt/pkg/util"
	pluginapi "kubevirt.io/kubevirt/pkg/virt-handler/device-manager/deviceplugin/v1beta1"
	"kubevirt.io/kubevirt/pkg/virt-handler/selinux"
)

//go:generate mockgen -source $GOFILE -package=$GOPACKAGE -destination=generated_mock_$GOFILE

type PermissionManager interface {
	ChownAtNoFollow(path *safepath.Path, uid, gid int) error
}

type permissionManager struct{}

func NewPermissionManager() PermissionManager {
	return &permissionManager{}
}

func (p *permissionManager) ChownAtNoFollow(path *safepath.Path, uid, gid int) error {
	return safepath.ChownAtNoFollow(path, uid, gid)
}

type SocketDevicePlugin struct {
	*DevicePluginBase
	socketDir  string
	socket     string
	socketName string
	executor   selinux.Executor
	p          PermissionManager
}

func (dpi *SocketDevicePlugin) Start(stop <-chan struct{}) (err error) {
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

func (dpi *SocketDevicePlugin) setSocketPermissions() error {
	socketPath := filepath.Join(dpi.socketDir, dpi.socket)
	prSock, err := safepath.NewPathNoFollow(socketPath)
	if err != nil {
		// For external sockets (like socat relays), the socket might not exist yet during initialization
		// or we might not have permission to access it. This is not necessarily fatal.
		log.DefaultLogger().Infof("Socket %s not accessible during initialization (this is normal for external sockets): %v", socketPath, err)
		return nil
	}

	// Only change ownership for sockets in KubeVirt-managed directories
	// External sockets (like socat relays) should not have their ownership changed
	if dpi.isKubeVirtManagedDirectory() {
		err = dpi.p.ChownAtNoFollow(prSock, util.NonRootUID, util.NonRootUID)
		if err != nil {
			return fmt.Errorf("error setting the permission the socket %s:%v", socketPath, err)
		}

		// Only relabel sockets in KubeVirt-managed directories
		if se, exists, err := dpi.executor.NewSELinux(); err == nil && exists {
			if err := selinux.RelabelFilesUnprivileged(se.IsPermissive(), prSock); err != nil {
				return fmt.Errorf("error relabeling required files: %v", err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to detect the presence of selinux: %v", err)
		}
	} else {
		// For external sockets, attempt relabeling but don't fail if it doesn't work
		if se, exists, err := dpi.executor.NewSELinux(); err == nil && exists {
			if err := selinux.RelabelFilesUnprivileged(se.IsPermissive(), prSock); err != nil {
				log.DefaultLogger().Infof("Could not relabel external socket %s (this may be normal): %v", socketPath, err)
			}
		}
	}

	return nil
}

func (dpi *SocketDevicePlugin) setSocketDirectoryPermissions() error {
	dir, err := safepath.NewPathNoFollow(dpi.socketDir)
	if err != nil {
		return fmt.Errorf("error opening the socket dir %s: %v", dpi.socketDir, err)
	}

	// Only change ownership for KubeVirt-managed directories, not system directories
	if dpi.isKubeVirtManagedDirectory() {
		err = dpi.p.ChownAtNoFollow(dir, util.NonRootUID, util.NonRootUID)
		if err != nil {
			return fmt.Errorf("error setting the permission the socket dir %s: %v", dpi.socketDir, err)
		}
		// Only relabel KubeVirt-managed directories, not system directories like /var/run
		if se, exists, err := dpi.executor.NewSELinux(); err == nil && exists {
			if err := selinux.RelabelFilesUnprivileged(se.IsPermissive(), dir); err != nil {
				return fmt.Errorf("error relabeling required files: %v", err)
			}
		} else if err != nil {
			return fmt.Errorf("failed to detect the presence of selinux: %v", err)
		}
	}

	return nil
}

// isKubeVirtManagedDirectory determines whether the socket directory is managed by KubeVirt
// and therefore safe to modify ownership and SELinux labels. System directories like /var/run
// should not be relabeled with container contexts.
func (dpi *SocketDevicePlugin) isKubeVirtManagedDirectory() bool {
	// KubeVirt-managed directories are typically under /var/run/kubevirt/
	return strings.HasPrefix(dpi.socketDir, "/var/run/kubevirt/") ||
		strings.HasPrefix(dpi.socketDir, "/run/kubevirt/")
}

func NewSocketDevicePlugin(socketName, socketDir, socket string, maxDevices int, executor selinux.Executor, p PermissionManager) (*SocketDevicePlugin, error) {
	dpi := &SocketDevicePlugin{
		DevicePluginBase: &DevicePluginBase{
			health:       make(chan deviceHealth),
			resourceName: fmt.Sprintf("%s/%s", DeviceNamespace, socketName),
			initialized:  false,
			lock:         &sync.Mutex{},
			done:         make(chan struct{}),
			deregistered: make(chan struct{}),
			socketPath:   SocketPath(strings.Replace(socketName, "/", "-", -1)),
		},
		socket:     socket,
		socketDir:  socketDir,
		socketName: socketName,
		executor:   executor,
		p:          p,
	}

	for i := 0; i < maxDevices; i++ {
		deviceId := dpi.socketName + strconv.Itoa(i)
		dpi.devs = append(dpi.devs, &pluginapi.Device{
			ID:     deviceId,
			Health: pluginapi.Healthy,
		})
	}
	if err := dpi.setSocketDirectoryPermissions(); err != nil {
		return nil, err
	}
	if err := dpi.setSocketPermissions(); err != nil {
		return nil, err
	}

	return dpi, nil
}

// Register registers the device plugin for the given resourceName with Kubelet.
func (dpi *SocketDevicePlugin) register() error {
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

func (dpi *SocketDevicePlugin) Allocate(ctx context.Context, r *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	log.DefaultLogger().Infof("Socket Allocate: resourceName: %s", dpi.socketName)
	log.DefaultLogger().Infof("Socket Allocate: request: %v", r.ContainerRequests)
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

func (dpi *SocketDevicePlugin) healthCheck() error {
	logger := log.DefaultLogger()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to creating a fsnotify watcher: %v", err)
	}
	defer watcher.Close()

	devicePath := filepath.Join(dpi.socketDir, dpi.socket)

	// Start watching the files before we check for their existence to avoid races
	err = watcher.Add(dpi.socketDir)
	if err != nil {
		return fmt.Errorf("failed to add the device root path to the watcher: %v", err)
	}

	_, err = os.Stat(devicePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("could not stat the device: %v", err)
		}
		logger.Warningf("device '%s' is not present, the device plugin can't expose it.", dpi.socketName)
		dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
	}
	logger.Infof("device '%s' is present.", devicePath)

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
			if event.Name == devicePath {
				// Health in this case is if the device path actually exists
				if event.Op == fsnotify.Create {
					logger.Infof("monitored device %s appeared", dpi.socketName)
					dpi.health <- deviceHealth{Health: pluginapi.Healthy}
				} else if (event.Op == fsnotify.Remove) || (event.Op == fsnotify.Rename) {
					logger.Infof("monitored device %s disappeared", dpi.socketName)
					dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
				}
			} else if event.Name == dpi.socketPath && event.Op == fsnotify.Remove {
				logger.Infof("device socket file for device %s was removed, kubelet probably restarted.", dpi.socketName)
				return nil
			}
		}
	}
}
