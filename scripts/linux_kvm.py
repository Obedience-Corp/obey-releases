"""Qualify real, normal-UID KVM access before building clean desktop guests.

This creates no guest memory or running CPU. VM boot, desktop and App acceptance
are separate. All KVM descriptors remain owned by this process and are closed.
"""
import errno
import json
import os
import platform
import stat
import sys

from verify_candidate import require_disposable

# Stable Linux KVM ABI, documented in Documentation/virt/kvm/api.rst.
KVM_GET_API_VERSION = 0xAE00
KVM_CREATE_VM = 0xAE01
KVM_CREATE_VCPU = 0xAE41


def probe(report):
    require_disposable()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise RuntimeError('clean Linux guest preflight requires native Linux x86_64')
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise RuntimeError('KVM must run as an ordinary, unchanged user ID')
    import fcntl

    descriptors = []
    report.update(uid=os.getuid(), gid=os.getgid(), kernel=platform.release(),
                  kvm_api=None, vm_created=False, vcpu_created=False,
                  descriptors_closed=False, hardware_virtualization_verified=False,
                  guest_boot_verified=False, desktop_verified=False,
                  app_first_use_verified=False, guest_reboot_verified=False)
    try:
        device = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        descriptors.append(device)
        info = os.fstat(device)
        if not stat.S_ISCHR(info.st_mode):
            raise RuntimeError('/dev/kvm is not a character device')
        report['device'] = {'major': os.major(info.st_rdev), 'minor': os.minor(info.st_rdev),
                            'mode': stat.S_IMODE(info.st_mode), 'gid': info.st_gid}
        report['kvm_api'] = fcntl.ioctl(device, KVM_GET_API_VERSION, 0)
        if report['kvm_api'] != 12:
            raise RuntimeError('unsupported KVM API; expected version12')
        vm = fcntl.ioctl(device, KVM_CREATE_VM, 0)
        descriptors.append(vm)
        os.set_inheritable(vm, False)
        report['vm_created'] = True
        cpu = fcntl.ioctl(vm, KVM_CREATE_VCPU, 0)
        descriptors.append(cpu)
        os.set_inheritable(cpu, False)
        report['vcpu_created'] = True
    finally:
        # Reverse order releases the vCPU, then VM, then device. Retain every
        # close error while still attempting to release the remaining handles.
        failures = []
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as error:
                failures.append(str(error))
        for descriptor in descriptors:
            try:
                os.fstat(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    failures.append(str(error))
            else:
                failures.append('KVM descriptor remained open')
        report['descriptors_closed'] = not failures
        if failures:
            report['cleanup_errors'] = failures
            raise RuntimeError('KVM descriptor cleanup failed: ' + '; '.join(failures))
    report['hardware_virtualization_verified'] = True


def main():
    report = {'schema': 'linux-kvm-preflight/v1', 'hardware_virtualization_verified': False}
    try:
        probe(report)
    except Exception as error:
        report['failure'] = str(error)
        print(json.dumps(report, indent=2))
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
