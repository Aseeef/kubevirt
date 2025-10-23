# See https://github.com/kubevirt/kubevirt/blob/main/docs/custom-rpms.md
export KUBEVIRT_CRI=docker  # tooling is VERY flimsy with podman
# Compile with QEMU and Libvirt with tdx support
export DOCKER_TAG=tdx-test-31;
export DOCKER_PREFIX=quay.io/rh-ee-aimran;
#make generate;
#make CUSTOM_REPO=tdx-repo.yaml SINGLE_ARCH="x86_64" LIBVIRT_VERSION=0:10.10.0-6.el9s.tdx QEMU_VERSION=17:9.1.0-25.el9s.tdx rpm-deps;
make push && make manifests;
kubectl apply -f _out/manifests/release/kubevirt-operator.yaml
#kubectl apply -f  _out/manifests/release/kubevirt-cr.yaml
oc delete vm tdx1
oc apply -f tdx-vm.yaml

# Create image pull secret

