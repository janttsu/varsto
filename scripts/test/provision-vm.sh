#!/usr/bin/env bash
# Create a disposable VM (libvirt + QEMU/KVM, cloud-init) and print its name on stdout.
#
# Usage: provision-vm.sh [--dry-run] <distro>
# Exit:  0 ok, 2 usage error, 3 environment problem. See TESTING.md.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

parse_common_flags "$@"
set -- "${ARGS[@]+"${ARGS[@]}"}"
[ "$#" -eq 1 ] && [ "$1" != "-h" ] && [ "$1" != "--help" ] || {
  log "usage: $(basename "$0") [--dry-run] <distro>"
  exit "$EXIT_USAGE"
}
DISTRO="$1"
lookup_image "$DISTRO"

need_tools virsh qemu-img ssh-keygen ssh curl sha512sum
ISO_TOOL=""
for t in xorriso genisoimage mkisofs cloud-localds; do
  if command -v "$t" >/dev/null 2>&1; then ISO_TOOL="$t"; break; fi
done
if [ -z "$ISO_TOOL" ]; then
  if [ "$DRY_RUN" = 1 ]; then ISO_TOOL=xorriso; else
    die "$EXIT_ENV" "need one of xorriso, genisoimage, mkisofs, cloud-localds to build the cloud-init seed"
  fi
fi

SUFFIX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
VM="${VM_PREFIX}${DISTRO}-${SUFFIX}"
STATE="$(vm_state_dir "$VM")"
BASE_VOL="varsto-base-${IMAGE_FILE}"
DISK_VOL="${VM}.qcow2"
SEED_VOL="${VM}-seed.iso"
NET="$VM"
# Bridge names are limited to 15 characters.
BRIDGE="vt${SUFFIX}"
CPUS="${VARSTO_VM_CPUS:-2}"
MEM_MIB="${VARSTO_VM_MEM_MIB:-2048}"
DISK_SIZE="${VARSTO_VM_DISK_SIZE:-10G}"

pick_subnet() {
  # An isolated 10.77.N.0/24 that no existing libvirt network uses.
  local n existing
  existing="$(virsh -q -c "$LIBVIRT_URI" net-list --all --name 2>/dev/null | while read -r net; do
    [ -n "$net" ] && virsh -q -c "$LIBVIRT_URI" net-dumpxml "$net" 2>/dev/null
  done || true)"
  for _ in $(seq 1 50); do
    n=$((RANDOM % 250 + 1))
    if ! printf '%s' "$existing" | grep -q "10\.77\.$n\."; then
      printf '%s' "$n"
      return 0
    fi
  done
  die "$EXIT_ENV" "no free 10.77.N.0/24 subnet found"
}

cleanup_on_failure() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$DRY_RUN" = 0 ] && [ "${VARSTO_KEEP_ON_FAIL:-0}" != 1 ]; then
    log "provision failed (exit $rc); cleaning up $VM"
    "$(dirname "${BASH_SOURCE[0]}")/destroy-vm.sh" "$VM" >&2 || true
  fi
}
trap cleanup_on_failure EXIT

if [ "$DRY_RUN" = 1 ]; then
  SUBNET_N=99
else
  SUBNET_N="$(pick_subnet)"
fi
HOST_IP="10.77.${SUBNET_N}.1"
VM_IP="10.77.${SUBNET_N}.10"
MAC="52:54:00:$(printf '%02x:%02x:%02x' "$((16#${SUFFIX:0:2}))" "$((16#${SUFFIX:2:2}))" "$SUBNET_N")"

log "provisioning $VM ($DISTRO) on $LIBVIRT_URI"

# 1. Base image: download once, verify the published SHA-512, upload to the pool once.
run mkdir -p "$CACHE_DIR/images" "$STATE"
IMAGE_PATH="$CACHE_DIR/images/$IMAGE_FILE"
if [ "$DRY_RUN" = 1 ] || [ ! -f "$IMAGE_PATH" ]; then
  run curl -fL --retry 3 -o "$IMAGE_PATH.part" "$IMAGE_URL"
  run curl -fL --retry 3 -o "$IMAGE_PATH.sums" "$CHECKSUM_URL"
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ (verify sha512 of $IMAGE_FILE against SHA512SUMS, then move into place)"
  else
    expected="$(grep " $IMAGE_FILE\$" "$IMAGE_PATH.sums" | cut -d' ' -f1)"
    actual="$(sha512sum "$IMAGE_PATH.part" | cut -d' ' -f1)"
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
      rm -f "$IMAGE_PATH.part" "$IMAGE_PATH.sums"
      die "$EXIT_ENV" "checksum mismatch for $IMAGE_FILE"
    fi
    mv "$IMAGE_PATH.part" "$IMAGE_PATH"
    rm -f "$IMAGE_PATH.sums"
  fi
fi
if [ "$DRY_RUN" = 1 ] || ! virsh -q -c "$LIBVIRT_URI" vol-info --pool "$POOL" "$BASE_VOL" >/dev/null 2>&1; then
  if [ "$DRY_RUN" = 1 ]; then
    IMAGE_BYTES=0
  else
    IMAGE_BYTES="$(stat -c %s "$IMAGE_PATH")"
  fi
  virsh_ vol-create-as "$POOL" "$BASE_VOL" "$IMAGE_BYTES" --format qcow2
  virsh_ vol-upload --pool "$POOL" "$BASE_VOL" "$IMAGE_PATH"
fi

# 2. Per-run SSH key and cloud-init seed.
run ssh-keygen -q -t ed25519 -N "" -C "$VM" -f "$STATE/id_ed25519"
if [ "$DRY_RUN" = 1 ]; then
  echo "+ (write $STATE/user-data and $STATE/meta-data, build $STATE/seed.iso with $ISO_TOOL, label cidata)"
else
  cat > "$STATE/meta-data" <<META
instance-id: $VM
local-hostname: $VM
META
  cat > "$STATE/user-data" <<USERDATA
#cloud-config
users:
  - name: $SSH_USER
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$STATE/id_ed25519.pub")
ssh_pwauth: false
package_update: false
USERDATA
  case "$ISO_TOOL" in
    cloud-localds) cloud-localds "$STATE/seed.iso" "$STATE/user-data" "$STATE/meta-data" ;;
    xorriso) xorriso -as mkisofs -quiet -output "$STATE/seed.iso" -volid cidata -joliet -rock \
      "$STATE/user-data" "$STATE/meta-data" ;;
    *) "$ISO_TOOL" -quiet -output "$STATE/seed.iso" -volid cidata -joliet -rock \
      "$STATE/user-data" "$STATE/meta-data" ;;
  esac
fi
if [ "$DRY_RUN" = 1 ]; then SEED_BYTES=0; else SEED_BYTES="$(stat -c %s "$STATE/seed.iso")"; fi
virsh_ vol-create-as "$POOL" "$SEED_VOL" "$SEED_BYTES" --format raw
virsh_ vol-upload --pool "$POOL" "$SEED_VOL" "$STATE/seed.iso"

# 3. Copy-on-write disk backed by the cached base image.
virsh_ vol-create-as "$POOL" "$DISK_VOL" "$DISK_SIZE" --format qcow2 \
  --backing-vol "$BASE_VOL" --backing-vol-format qcow2

# 4. Isolated network: no <forward> element, so the VM cannot reach the LAN or the internet.
NET_XML="$STATE/network.xml"
DOM_XML="$STATE/domain.xml"
if [ "$DRY_RUN" = 1 ]; then
  echo "+ (write $NET_XML: isolated network $NET, bridge $BRIDGE, 10.77.${SUBNET_N}.0/24, static lease $VM_IP)"
else
  cat > "$NET_XML" <<NETXML
<network>
  <name>$NET</name>
  <bridge name='$BRIDGE' stp='off' delay='0'/>
  <ip address='$HOST_IP' netmask='255.255.255.0'>
    <dhcp>
      <host mac='$MAC' name='$VM' ip='$VM_IP'/>
    </dhcp>
  </ip>
</network>
NETXML
fi
virsh_ net-define "$NET_XML"
virsh_ net-start "$NET"

# 5. Domain. UEFI is required: the Debian cloud image boot-loops under SeaBIOS.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
  DOM_TYPE=kvm
  CPU_XML="<cpu mode='host-passthrough'/>"
else
  DOM_TYPE=qemu
  CPU_XML="<cpu mode='custom' match='exact'><model>qemu64</model></cpu>"
  log "note: /dev/kvm not usable; falling back to slow software emulation"
fi
if [ "$DRY_RUN" = 1 ]; then
  echo "+ (write $DOM_XML: $DOM_TYPE domain $VM, $CPUS vCPU, ${MEM_MIB} MiB, disks $DISK_VOL + $SEED_VOL from pool $POOL)"
else
  cat > "$DOM_XML" <<DOMXML
<domain type='$DOM_TYPE'>
  <name>$VM</name>
  <memory unit='MiB'>$MEM_MIB</memory>
  <vcpu>$CPUS</vcpu>
  <os firmware='efi'><type arch='x86_64' machine='q35'>hvm</type><firmware><feature enabled='no' name='secure-boot'/></firmware><boot dev='hd'/></os>
  <features><acpi/><apic/></features>
  $CPU_XML
  <devices>
    <disk type='volume' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source pool='$POOL' volume='$DISK_VOL'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='volume' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source pool='$POOL' volume='$SEED_VOL'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='$NET'/>
      <mac address='$MAC'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'><target port='0'/></serial>
    <console type='pty'><target type='serial' port='0'/></console>
    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>
  </devices>
</domain>
DOMXML
fi
virsh_ define "$DOM_XML"
virsh_ start "$VM"

# 6. Record how to reach the VM, then wait for SSH.
if [ "$DRY_RUN" = 1 ]; then
  echo "+ (write $STATE/meta: ip=$VM_IP user=$SSH_USER distro=$DISTRO)"
  echo "+ (wait up to 300 s for ssh $SSH_USER@$VM_IP)"
else
  printf 'ip=%s\nuser=%s\ndistro=%s\nnetwork=%s\n' "$VM_IP" "$SSH_USER" "$DISTRO" "$NET" > "$STATE/meta"
  deadline=$((SECONDS + 300))
  until ssh -i "$STATE/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 \
    "$SSH_USER@$VM_IP" true 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      die "$EXIT_ENV" "VM $VM did not accept SSH within 300 s"
    fi
    sleep 3
  done
fi

printf '%s\n' "$VM"
