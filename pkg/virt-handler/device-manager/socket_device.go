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
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

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
	ChpermAtNoFollow(path *safepath.Path, uid, gid int, mode os.FileMode) error
	IsAccessibleByUser(path *safepath.Path, uid int) (bool, error)
	getGroupsForUID(uid int) ([]int, error)
}

type permissionManager struct{}

func NewPermissionManager() PermissionManager {
	return &permissionManager{}
}

func (p *permissionManager) ChownAtNoFollow(path *safepath.Path, uid, gid int) error {
	return safepath.ChownAtNoFollow(path, uid, gid)
}

func (p *permissionManager) ChpermAtNoFollow(path *safepath.Path, uid, gid int, mode os.FileMode) error {
	return safepath.ChpermAtNoFollow(path, uid, gid, mode)
}

func (p *permissionManager) IsAccessibleByUser(path *safepath.Path, uid int) (bool, error) {
	// Get file info using safepath
	fileInfo, err := safepath.StatAtNoFollow(path)
	if err != nil {
		return false, err
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("failed to get stat information")
	}

	mode := fileInfo.Mode()

	// Check if user is the owner
	if stat.Uid == uint32(uid) {
		// Owner: check user read+write permissions (both required for sockets)
		return mode&0600 == 0600, nil
	}

	// Get user's groups to check group membership
	groups, err := p.getGroupsForUID(uid)
	if err != nil {
		// If we can't get groups, fall back to checking others permissions only
		log.DefaultLogger().V(4).Infof("Unable to get groups for UID %d: %v, checking others permissions", uid, err)
	} else {
		// Check if user is in the file's group
		for _, gid := range groups {
			if stat.Gid == uint32(gid) {
				// Group: check group read+write permissions (both required for sockets)
				return mode&0060 == 0060, nil
			}
		}
	}

	// Otherwise check others permissions (read+write required)
	return mode&0006 == 0006, nil
}

// getGroupsForUID returns all group IDs that the given user belongs to
func (p *permissionManager) getGroupsForUID(uid int) ([]int, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, err
	}

	gidStrings, err := u.GroupIds()
	if err != nil {
		return nil, err
	}

	gids := make([]int, 0, len(gidStrings))
	for _, gidStr := range gidStrings {
		gid, err := strconv.Atoi(gidStr)
		if err != nil {
			log.DefaultLogger().V(4).Infof("Unable to convert group ID %s to int: %v", gidStr, err)
			continue
		}
		gids = append(gids, gid)
	}

	return gids, nil
}

type SocketDevicePlugin struct {
	*DevicePluginBase
	socketDir  string
	socketFile string
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
	prSock, err := safepath.JoinAndResolveWithRelativeRoot("/", dpi.socketDir, dpi.socketFile)
	if err != nil {
		return fmt.Errorf("error opening the socket %s/%s: %v", dpi.socketDir, dpi.socketName, err)
	}
	// Set permissions to 0660 (rw-rw----) to ensure read+write for owner and group
	err = dpi.p.ChpermAtNoFollow(prSock, util.NonRootUID, util.NonRootUID, 0660)
	if err != nil {
		return fmt.Errorf("error setting the permission the socket %s/%s:%v", dpi.socketDir, dpi.socketName, err)
	}
	if se, exists, err := dpi.executor.NewSELinux(); err == nil && exists {
		if err := selinux.RelabelFilesUnprivileged(se.IsPermissive(), prSock); err != nil {
			return fmt.Errorf("error relabeling required files: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to detect the presence of selinux: %v", err)
	}

	return nil
}

func (dpi *SocketDevicePlugin) setSocketDirectoryPermissions() error {
	dir, err := safepath.JoinAndResolveWithRelativeRoot("/", dpi.socketDir)
	if err != nil {
		return fmt.Errorf("error opening the socket dir %s: %v", dpi.socketDir, err)
	}
	// Set permissions to 0770 (rwxrwx---) to ensure read+write+execute for owner and group
	err = dpi.p.ChpermAtNoFollow(dir, util.NonRootUID, util.NonRootUID, 0770)
	if err != nil {
		return fmt.Errorf("error setting the permission the socket dir %s: %v", dpi.socketDir, err)
	}
	if se, exists, err := dpi.executor.NewSELinux(); err == nil && exists {
		if err := selinux.RelabelFilesUnprivileged(se.IsPermissive(), dir); err != nil {
			return fmt.Errorf("error relabeling required files: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to detect the presence of selinux: %v", err)
	}

	return nil
}

func NewSocketDevicePlugin(socketName, socketDir, socketFile string, maxDevices int, executor selinux.Executor, p PermissionManager) (*SocketDevicePlugin, error) {
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
		socketFile: socketFile,
		socketDir:  socketDir,
		socketName: socketName,
		executor:   executor,
		p:          p,
	}

	for i := 0; i < maxDevices; i++ {
		deviceId := dpi.socketName + strconv.Itoa(i)
		dpi.devs = append(dpi.devs, &pluginapi.Device{
			ID:     deviceId,
			Health: pluginapi.Unhealthy,
		})
	}

	return dpi, nil
}

func (dpi *SocketDevicePlugin) ensurePermissions() bool {
	logger := log.DefaultLogger()

	// Set directory permissions first
	if err := dpi.setSocketDirectoryPermissions(); err != nil {
		logger.Reason(err).Warningf("Failed to set socket directory permissions")
		return false
	} else {
		logger.Infof("Successfully set permissions on socket directory %s", dpi.socketDir)
	}

	// Then set socket permissions
	if err := dpi.setSocketPermissions(); err != nil {
		logger.Reason(err).Warningf("Failed to set socket permissions")
		return false
	} else {
		logger.Infof("Successfully set permissions on socket %s/%s", dpi.socketDir, dpi.socketFile)
		return true
	}
}

// checkSocketAccessible verifies if the qemu user can access the socket
func (dpi *SocketDevicePlugin) checkSocketAccessible() bool {
	logger := log.DefaultLogger()

	sock, err := safepath.JoinAndResolveWithRelativeRoot("/", dpi.socketDir, dpi.socketFile)
	if err != nil {
		logger.Reason(err).Warningf("error opening the socket path %s/%s", dpi.socketDir, dpi.socketFile)
		return false
	}

	// Check if qemu user (util.NonRootUID) can access the socket
	accessible, err := dpi.p.IsAccessibleByUser(sock, util.NonRootUID)
	if err != nil {
		logger.Reason(err).Warningf("error checking accessibility of socket %s/%s", dpi.socketDir, dpi.socketFile)
		return false
	}

	if !accessible {
		logger.Warningf("socket %s/%s is NOT accessible to qemu user", dpi.socketDir, dpi.socketFile)
	} else {
		logger.Infof("socket %s/%s is accessible to qemu user", dpi.socketDir, dpi.socketFile)
	}

	return accessible
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

	// Socket directory is mounted into the container at the same path as on the host
	devicePath := filepath.Join(dpi.socketDir, dpi.socketFile)

	// Try to watch the socket directory, fallback to parent if it doesn't exist
	err = watcher.Add(dpi.socketDir)
	if err != nil {
		// If the directory doesn't exist, watch its parent
		parentDir := filepath.Dir(dpi.socketDir)
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
		logger.Warningf("socket '%s' is not present, marking devices as unhealthy", devicePath)
		dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
	} else {
		logger.Infof("socket '%s' is present", devicePath)
		if !dpi.checkSocketAccessible() {
			dpi.ensurePermissions()
		}
		dpi.health <- deviceHealth{Health: pluginapi.Healthy}
	}

	// Watch the device plugin socket directory
	dirName := filepath.Dir(dpi.socketPath)
	err = watcher.Add(dirName)
	if err != nil {
		return fmt.Errorf("failed to add the device-plugin kubelet path to the watcher: %v", err)
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
			if event.Name == dpi.socketDir && event.Op == fsnotify.Create {
				logger.Infof("socket directory %s was created, adding watcher", dpi.socketDir)
				if err := watcher.Add(dpi.socketDir); err != nil {
					logger.Reason(err).Errorf("failed to add socket directory to watcher")
				}
			}

			if event.Name == devicePath {
				switch event.Op {
				case fsnotify.Create:
					logger.Infof("monitored device %s appeared", dpi.socketName)
					if !dpi.checkSocketAccessible() {
						if dpi.ensurePermissions() {
							dpi.health <- deviceHealth{Health: pluginapi.Healthy}
						} else {
							dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
						}
					} else {
						dpi.health <- deviceHealth{Health: pluginapi.Healthy}
					}
				case fsnotify.Remove, fsnotify.Rename:
					logger.Infof("monitored device %s disappeared", dpi.socketName)
					dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
				case fsnotify.Chmod:
					logger.Infof("monitored device %s had permissions changed", dpi.socketName)
					if !dpi.checkSocketAccessible() {
						if dpi.ensurePermissions() {
							dpi.health <- deviceHealth{Health: pluginapi.Healthy}
						} else {
							dpi.health <- deviceHealth{Health: pluginapi.Unhealthy}
						}
					}
				}
			} else if event.Name == dpi.socketPath && event.Op == fsnotify.Remove {
				logger.Infof("device socket file for device %s was removed, kubelet probably restarted", dpi.socketName)
				return nil
			}
		}
	}
}
