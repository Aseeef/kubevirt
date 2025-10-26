# See https://github.com/kubevirt/kubevirt/blob/main/docs/custom-rpms.md
export KUBEVIRT_CRI=docker  # tooling is VERY flimsy with podman
# Compile with QEMU and Libvirt with tdx support
export DOCKER_TAG=tdx-test-40;
export DOCKER_PREFIX=quay.io/rh-ee-aimran;
sudo -E make generate;
sudo -E make rpm-deps;
sudo -E make push && sudo -E make manifests;
kubectl apply -f _out/manifests/release/kubevirt-operator.yaml
#kubectl apply -f  _out/manifests/release/kubevirt-cr.yaml
oc delete vm tdx1
oc apply -f tdx-vm.yaml

# Create image pull secret

