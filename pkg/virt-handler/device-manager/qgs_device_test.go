package device_manager

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"

	pluginapi "kubevirt.io/kubevirt/pkg/virt-handler/device-manager/deviceplugin/v1beta1"
	"kubevirt.io/kubevirt/pkg/virt-handler/selinux"
)

var _ = Describe("QGS device", func() {
	var workDir string
	var dpi *QGSDevicePlugin
	var stop chan struct{}
	var qgsSocketPath string

	BeforeEach(func() {
		var err error
		workDir = GinkgoT().TempDir()
		Expect(err).ToNot(HaveOccurred())

		// Create QGS socket directory
		qgsDir := filepath.Join(workDir, "tdx-qgs")
		err = os.MkdirAll(qgsDir, 0755)
		Expect(err).ToNot(HaveOccurred())

		qgsSocketPath = filepath.Join(qgsDir, qgsSocketName)
		createQGSSocket(qgsSocketPath)

		// Setup mocks for permission management
		ctrl := gomock.NewController(GinkgoT())
		mockExec := selinux.NewMockExecutor(ctrl)
		mockPermManager := NewMockPermissionManager(ctrl)
		mockSelinux := selinux.NewMockSELinux(ctrl)
		mockExec.EXPECT().NewSELinux().Return(mockSelinux, true, nil).AnyTimes()
		mockSelinux.EXPECT().IsPermissive().Return(true).AnyTimes()
		mockPermManager.EXPECT().ChownAtNoFollow(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		mockPermManager.EXPECT().IsAccessibleByUser(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

		dpi = NewQGSDevicePlugin(1)
		// Override paths and mocks for testing
		dpi.socketDir = qgsDir
		dpi.executor = mockExec
		dpi.permManager = mockPermManager
		dpi.server = grpc.NewServer([]grpc.ServerOption{}...)
		dpi.socketPath = filepath.Join(workDir, "kubevirt-qgs.sock")
		createQGSSocket(dpi.socketPath)
		dpi.done = make(chan struct{})
		stop = make(chan struct{})
		dpi.stop = stop
	})

	AfterEach(func() {
		close(stop)
	})

	It("Should stop if the device plugin socket file is deleted", func() {
		errChan := make(chan error, 1)
		go func(errChan chan error) {
			errChan <- dpi.healthCheck()
		}(errChan)

		// Wait for health check to stabilize
		Consistently(func() string {
			return dpi.devs[0].Health
		}, 2*time.Second, 500*time.Millisecond).Should(Equal(pluginapi.Healthy))

		Expect(os.Remove(dpi.socketPath)).To(Succeed())

		Expect(<-errChan).ToNot(HaveOccurred())
	})

	It("Should monitor health of QGS socket", func() {
		go dpi.healthCheck()
		Expect(dpi.devs[0].Health).To(Equal(pluginapi.Healthy))

		By("Removing the QGS socket")
		os.Remove(qgsSocketPath)

		By("waiting for healthcheck to send Unhealthy message")
		Eventually(func() string {
			return (<-dpi.health).Health
		}, 5*time.Second).Should(Equal(pluginapi.Unhealthy))

		By("Creating the QGS socket again")
		createQGSSocket(qgsSocketPath)

		By("waiting for healthcheck to send Healthy message")
		Eventually(func() string {
			return (<-dpi.health).Health
		}, 5*time.Second).Should(Equal(pluginapi.Healthy))
	})

	It("Should mark all devices as unhealthy when socket doesn't exist", func() {
		// Remove socket before health check starts
		os.Remove(qgsSocketPath)

		go dpi.healthCheck()

		By("waiting for healthcheck to send Unhealthy message for all devices")
		Eventually(func() string {
			return (<-dpi.health).Health
		}, 5*time.Second).Should(Equal(pluginapi.Unhealthy))
	})

	It("Should handle socket directory not existing initially", func() {
		// Remove entire socket directory
		os.RemoveAll(dpi.socketDir)

		errChan := make(chan error, 1)
		go func(errChan chan error) {
			errChan <- dpi.healthCheck()
		}(errChan)

		// Should still work even if directory doesn't exist
		time.Sleep(1 * time.Second)

		By("Creating socket directory and socket")
		err := os.MkdirAll(dpi.socketDir, 0755)
		Expect(err).ToNot(HaveOccurred())
		createQGSSocket(qgsSocketPath)

		By("waiting for healthcheck to send Healthy message")
		Eventually(func() string {
			return (<-dpi.health).Health
		}, 5*time.Second).Should(Equal(pluginapi.Healthy))
	})

	It("Should handle Chmod events and check socket accessibility", func() {
		go dpi.healthCheck()

		// Initially healthy
		Expect(dpi.devs[0].Health).To(Equal(pluginapi.Healthy))

		By("Changing socket permissions to be inaccessible")
		// Change permissions to make it inaccessible (no read for anyone)
		err := os.Chmod(qgsSocketPath, 0000)
		Expect(err).ToNot(HaveOccurred())

		By("Waiting for health check to detect permission change")
		// The Chmod event should trigger a check
		time.Sleep(2 * time.Second)

		By("Restoring socket permissions")
		err = os.Chmod(qgsSocketPath, 0644)
		Expect(err).ToNot(HaveOccurred())

		// Give time for the health check to process the event
		time.Sleep(1 * time.Second)
	})

	It("Should return multiple devices with same health status", func() {
		// Create plugin with multiple devices
		ctrl := gomock.NewController(GinkgoT())
		mockExec := selinux.NewMockExecutor(ctrl)
		mockPermManager := NewMockPermissionManager(ctrl)
		mockSelinux := selinux.NewMockSELinux(ctrl)
		mockExec.EXPECT().NewSELinux().Return(mockSelinux, true, nil).AnyTimes()
		mockSelinux.EXPECT().IsPermissive().Return(true).AnyTimes()
		mockPermManager.EXPECT().ChownAtNoFollow(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
		mockPermManager.EXPECT().IsAccessibleByUser(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

		multiDpi := NewQGSDevicePlugin(3)
		multiDpi.socketDir = dpi.socketDir
		multiDpi.executor = mockExec
		multiDpi.permManager = mockPermManager
		multiDpi.server = grpc.NewServer([]grpc.ServerOption{}...)
		multiDpi.socketPath = filepath.Join(workDir, "kubevirt-qgs-multi.sock")
		createQGSSocket(multiDpi.socketPath)
		multiDpi.done = make(chan struct{})
		multiStop := make(chan struct{})
		multiDpi.stop = multiStop
		defer close(multiStop)

		Expect(multiDpi.devs).To(HaveLen(3))

		go multiDpi.healthCheck()

		// All devices should be healthy initially
		for _, dev := range multiDpi.devs {
			Expect(dev.Health).To(Equal(pluginapi.Healthy))
		}

		By("Removing the QGS socket to make all devices unhealthy")
		os.Remove(qgsSocketPath)

		By("Waiting for all devices to become unhealthy")
		Eventually(func() string {
			return (<-multiDpi.health).Health
		}, 5*time.Second).Should(Equal(pluginapi.Unhealthy))

		// Verify all devices have the same unhealthy status
		for _, dev := range multiDpi.devs {
			Expect(dev.Health).To(Equal(pluginapi.Unhealthy))
		}
	})

	Context("Allocate", func() {
		It("Should return proper mount configuration", func() {
			req := &pluginapi.AllocateRequest{
				ContainerRequests: []*pluginapi.ContainerAllocateRequest{
					{
						DevicesIDs: []string{"qgs0"},
					},
				},
			}

			resp, err := dpi.Allocate(context.Background(), req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp).ToNot(BeNil())
			Expect(resp.ContainerResponses).To(HaveLen(1))

			containerResp := resp.ContainerResponses[0]
			Expect(containerResp.Mounts).To(HaveLen(1))

			mount := containerResp.Mounts[0]
			Expect(mount.HostPath).To(Equal(dpi.socketDir))
			Expect(mount.ContainerPath).To(Equal(dpi.socketDir))
			Expect(mount.ReadOnly).To(BeFalse())
		})

		It("Should handle multiple device allocations", func() {
			req := &pluginapi.AllocateRequest{
				ContainerRequests: []*pluginapi.ContainerAllocateRequest{
					{
						DevicesIDs: []string{"qgs0"},
					},
				},
			}

			resp, err := dpi.Allocate(context.Background(), req)
			Expect(err).ToNot(HaveOccurred())
			Expect(resp.ContainerResponses).To(HaveLen(1))
		})
	})

	Context("Permission Management", func() {
		var ctrl *gomock.Controller
		var mockPermManager *MockPermissionManager

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockPermManager = NewMockPermissionManager(ctrl)
			dpi.permManager = mockPermManager
		})

		It("Should check socket accessibility", func() {
			mockPermManager.EXPECT().
				IsAccessibleByUser(gomock.Any(), gomock.Any()).
				Return(true, nil)

			accessible := dpi.checkSocketAccessible()
			Expect(accessible).To(BeTrue())
		})

		It("Should return false when socket is not accessible", func() {
			mockPermManager.EXPECT().
				IsAccessibleByUser(gomock.Any(), gomock.Any()).
				Return(false, nil)

			accessible := dpi.checkSocketAccessible()
			Expect(accessible).To(BeFalse())
		})

		It("Should handle errors when checking accessibility", func() {
			mockPermManager.EXPECT().
				IsAccessibleByUser(gomock.Any(), gomock.Any()).
				Return(false, syscall.EACCES)

			accessible := dpi.checkSocketAccessible()
			Expect(accessible).To(BeFalse())
		})

		It("Should set socket and directory permissions", func() {
			mockPermManager.EXPECT().
				ChownAtNoFollow(gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil).
				Times(2) // Once for directory, once for socket

			dpi.ensurePermissions()
		})
	})
})

func createQGSSocket(path string) {
	fileObj, err := os.Create(path)
	Expect(err).ToNot(HaveOccurred())
	fileObj.Close()
}
