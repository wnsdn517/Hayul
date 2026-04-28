import json
import re
import os
import glob
import base64
import tempfile
import lxml.etree
import subprocess
import argparse

from pathlib import Path
from zipfile import ZipFile
from datetime import datetime

import pyaxml

from ppadb.client import Client as AdbClient
from ppadb.device import Device

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

client = AdbClient()

HAYUL_DEBUG = False

SHARED_ID = "seola.patcher.abcde.shared"
PATCHER_SIG_NAME = "dev.seola.apppatcher.sig.orig"
KEY_PASSWORD = "aaaaaa"

# Frida gadget 파일명 (assets/frida/ 하위에 ABI별로 배치)
# assets/frida/arm64-v8a/libfrida-gadget.so
# assets/frida/armeabi-v7a/libfrida-gadget.so
# assets/frida/x86/libfrida-gadget.so
# assets/frida/x86_64/libfrida-gadget.so
FRIDA_ABIS = ["arm64-v8a", "armeabi-v7a", "x86", "x86_64"]


def main():
    parser = argparse.ArgumentParser(description="APK Patcher")
    parser.add_argument(
        "--include-frida",
        action="store_true",
        help="Frida Gadget을 APK에 주입합니다",
    )
    parser.add_argument(
        "--apk",
        type=str,
        help="로컬 APK 파일 경로 (지정 시 ADB 불필요)",
    )
    args = parser.parse_args()

    check_file(include_frida=args.include_frida)

    with tempfile.TemporaryDirectory() as dir:
        if args.apk:
            # 로컬 APK 모드
            apk_path = os.path.abspath(args.apk)
            if not os.path.isfile(apk_path):
                raise Exception(f"파일을 찾을 수 없습니다: {apk_path}")

            base_path = os.path.join(dir, "base.apk")
            import shutil
            shutil.copy2(apk_path, base_path)
            print(f"{apk_path} 로 진행합니다.")

        else:
            # ADB 모드 (기존)
            dev = client.devices()
            if not dev:
                raise Exception("연결된 디바이스가 존재하지 않습니다")

            dev: Device = dev[0]
            print(dev.get_serial_no(), "로 진행합니다.")
            package_name = input("패키지 명을 입력해주세요 > ").strip()
            apks = get_apks(dev, package_name)
            extract(dev, dir, apks)
            base_path = os.path.join(dir, "base.apk")

        out_path = os.path.join(dir, "patched.apk")

        patch(
            base_path,
            out_path,
            get_signature(base_path),
            include_frida=args.include_frida,
        )

        if HAYUL_DEBUG:
            print("DEBUG", dir)
            input("press enter to continue")

        os.remove(base_path)

        align(dir)
        sign(dir)

        outdir = os.path.join(get_base_path(), f"patched-{generate_date_time()}")
        os.mkdir(outdir)

        for name in glob.glob("*-aligned.apk", root_dir=dir):
            os.rename(os.path.join(dir, name), os.path.join(outdir, name))

    print(outdir, "에 성공적으로 패치되었습니다")


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _update_android_attribute(type: str, attrib: dict[str, str], name: str, value: str):
    aname = ANDROID_NS + name
    attrib.pop(aname, None)

    attrIdx = ATTRIB_IDX_DATA[type][name]
    for idx, attribName in enumerate(attrib.keys()):
        if attribName.startswith(ANDROID_NS):
            onlyName = attribName[len(ANDROID_NS):]

            if ATTRIB_IDX_DATA[type][onlyName] > attrIdx:
                keys = list(attrib.keys())
                left = dict(map(lambda key: (key, attrib[key]), keys[:idx]))
                right = dict(map(lambda key: (key, attrib[key]), keys[idx:]))

                return {
                    **left,
                    aname: value,
                    **right,
                }

    keys = list(attrib.keys())
    return {**dict(map(lambda key: (key, attrib[key]), keys)), aname: value}


def patch_manifest_axml(
    axml: bytes,
    sharedUserId: str | None = None,
    appComponentFactory: str | None = None,
    debuggable: str | None = None,
    applicationProcess: str | None = None,
    extractNativeLibs: str | None = None,
):
    axml, _ = pyaxml.AXML.from_axml(axml)

    manifest: lxml.etree.ElementBase = axml.to_xml()
    application: lxml.etree.ElementBase = manifest.find("./application")

    manifestAttrib: dict[str, str] = {**manifest.attrib}
    applicationAttrib: dict[str, str] = {**application.attrib}

    if sharedUserId is not None:
        manifestAttrib = _update_android_attribute(
            "manifest", manifestAttrib, "sharedUserId", sharedUserId
        )

    if appComponentFactory is not None:
        applicationAttrib = _update_android_attribute(
            "application", applicationAttrib, "appComponentFactory", appComponentFactory
        )

    if debuggable is not None:
        applicationAttrib = _update_android_attribute(
            "application", applicationAttrib, "debuggable", debuggable
        )

    if applicationProcess is not None:
        applicationAttrib = _update_android_attribute(
            "application", applicationAttrib, "process", applicationProcess
        )

    # Frida gadget 로드를 위해 extractNativeLibs=true 강제
    if extractNativeLibs is not None:
        applicationAttrib = _update_android_attribute(
            "application", applicationAttrib, "extractNativeLibs", extractNativeLibs
        )

    manifest.attrib.clear()
    for k, v in manifestAttrib.items():
        manifest.attrib[k] = v

    application.attrib.clear()
    for k, v in applicationAttrib.items():
        application.attrib[k] = v

    axmlOut = pyaxml.axml.AXML()
    axmlOut.from_xml(manifest)

    return axmlOut.pack()


def inject_frida_gadget(zf_src: ZipFile, zf_dst: ZipFile):
    """
    ABI별 frida-gadget .so를 lib/<abi>/libfrida-gadget.so 로 삽입.
    기기에 실제로 존재하는 ABI lib 폴더 기준으로만 삽입 (없으면 전체 삽입).
    """
    # 원본 APK에 있는 lib/<abi>/ 목록 추출
    existing_abis = set()
    for entry in zf_src.infolist():
        m = re.match(r"lib/([^/]+)/", entry.filename)
        if m:
            existing_abis.add(m.group(1))

    # 원본에 lib 폴더가 없으면 지원 ABI 전체 삽입
    target_abis = existing_abis & set(FRIDA_ABIS) if existing_abis else set(FRIDA_ABIS)

    injected = []
    for abi in target_abis:
        gadget_asset = get_frida_gadget_path(abi)
        if not os.path.isfile(gadget_asset):
            print(f"  [frida] {abi} 가젯 파일 없음, 건너뜀: {gadget_asset}")
            continue

        dest_path = f"lib/{abi}/libfrida-gadget.so"

        # 이미 삽입되어 있으면 덮어쓰기
        with open(gadget_asset, "rb") as f:
            zf_dst.writestr(dest_path, f.read())

        print(f"  [frida] {dest_path} 삽입 완료")
        injected.append(abi)

    if not injected:
        print("  [frida] 주입된 ABI 없음 — assets/frida/<abi>/libfrida-gadget.so 파일을 확인하세요")

    return injected


def extract(dev: Device, dir: str, apks: list[str]):
    for apk in apks:
        name = os.path.basename(apk)
        print("Extract", name)
        dev.pull(apk, os.path.join(dir, name))


def check_file(include_frida: bool = False):
    if not os.path.isfile(get_key_path()):
        print("KEY.jks가 존재하지 않습니다.")
        print(
            "keytool -genkey -v -keystore KEY.jks -keyalg RSA -keysize 2048 -validity 10000"
        )
        print(
            f"위 명령어를 이용하여 생성해주세요. 비밀번호는 {KEY_PASSWORD}으로 해주세요. (java가 설치되어있어야 합니다)"
        )
        exit(1)

    if include_frida:
        found_any = False
        for abi in FRIDA_ABIS:
            if os.path.isfile(get_frida_gadget_path(abi)):
                found_any = True
                break
        if not found_any:
            print("Frida 가젯 파일이 없습니다.")
            print(f"assets/frida/<abi>/libfrida-gadget.so 형태로 배치해주세요.")
            print(f"지원 ABI: {', '.join(FRIDA_ABIS)}")
            print("다운로드: https://github.com/frida/frida/releases")
            exit(1)


def patch(base_path: str, out_path: str, signature: str, include_frida: bool = False):
    print("패치 중...")

    already_patched = False
    dex_list = []

    with ZipFile(base_path) as zf:
        with ZipFile(out_path, "w") as zf2:
            max_dex = 1
            for info in zf.infolist():
                if info.filename == PATCHER_SIG_NAME:
                    already_patched = True
                    continue

                if info.filename == "AndroidManifest.xml":
                    patched = patch_manifest_axml(
                        zf.read(info),
                        sharedUserId=SHARED_ID,
                        appComponentFactory="dev.seola.apppatcher.stub.PatcherAppComponentFactory",
                        # Frida 가젯 주입 시 extractNativeLibs 강제 활성화
                        extractNativeLibs="true" if include_frida else None,
                    )

                    zf2.writestr(
                        zinfo_or_arcname=info,
                        data=patched,
                        compress_type=info.compress_type,
                    )

                    print("manifest patched")
                    continue

                # Frida 주입 시 기존 libfrida-gadget.so는 덮어쓸 것이므로 스킵
                if include_frida and re.match(r"lib/[^/]+/libfrida-gadget\.so", info.filename):
                    print(f"  [frida] 기존 {info.filename} 교체 예정, 스킵")
                    continue

                m = re.match(r"classes(\d+)\.dex", info.filename)
                if m:
                    max_dex = max(max_dex, int(m.group(1)))
                    dex_list.append(info.filename)
                    continue

                zf2.writestr(
                    zinfo_or_arcname=info,
                    data=zf.read(info),
                    compress_type=info.compress_type,
                )

            if already_patched:
                signature = zf.read(PATCHER_SIG_NAME).decode()
                dex_list.remove(f"classes{max_dex}.dex")
                max_dex -= 1

            for name in dex_list:
                zf2.writestr(name, zf.read(name))

            with open(get_asset_path("patcher.dex"), "rb") as f:
                zf2.writestr(f"classes{max_dex + 1}.dex", f.read())
            zf2.writestr(PATCHER_SIG_NAME, signature)

            # Frida 가젯 삽입
            if include_frida:
                print("Frida Gadget 주입 중...")
                inject_frida_gadget(zf, zf2)


def sign(dir: str):
    for name in glob.glob("*-aligned.apk", root_dir=dir):
        print("Sign", name)

        name = os.path.join(dir, name)

        res = subprocess.call(
            args=[
                "java",
                "-jar",
                get_asset_path("apksigner.jar"),
                "sign",
                "--ks",
                get_key_path(),
                "--v2-signing-enabled",
                "true",
                "--ks-pass",
                f"pass:{KEY_PASSWORD}",
                name,
            ]
        )

        if res != 0:
            raise Exception("Sign 실패")


def align(dir: str):
    for apk in os.listdir(dir):
        print("Align", os.path.basename(apk))

        res = subprocess.call(
            args=[
                "java",
                "-jar",
                get_asset_path("zipalign-java.jar"),
                os.path.join(dir, apk),
                os.path.join(dir, apk.rsplit(".", 1)[0] + "-aligned.apk"),
            ]
        )

        if res != 0:
            raise Exception("Align 실패")


def generate_date_time():
    now = datetime.now()
    return now.strftime("%Y%m%d%H%M%S")


def get_apks(dev: Device, package_name: str):
    res: str = dev.shell(f"pm path {package_name}").strip()
    if not res:
        raise Exception("경로를 가져오지 못했습니다")

    apks = []
    for line in res.split("\n"):
        if line.startswith("package:"):
            apks.append(line[8:])

    if not apks:
        raise Exception("경로를 가져오지 못했습니다")

    return apks


def get_signature(apk_path: str):
    res = subprocess.check_output(
        args=[
            "java",
            "-jar",
            get_asset_path("apksigner.jar"),
            "verify",
            "--print-certs-pem",
            apk_path,
        ],
        text=True,
    )

    cert = base64.b64decode(
        res.split("-----END CERTIFICATE-----")[0]
        .split("-----BEGIN CERTIFICATE-----")[1]
        .replace("\n", "")
        .strip()
    )

    cert = x509.load_der_x509_certificate(cert)
    return cert.public_bytes(Encoding.DER).hex()


def get_base_path():
    return str(Path(__file__).parent)


def get_key_path():
    return str(Path(__file__).parent / "KEY.jks")


def get_asset_path(name: str):
    return str(Path(__file__).parent / "assets" / name)


def get_frida_gadget_path(abi: str):
    return str(Path(__file__).parent / "assets" / "frida" / abi / "libfrida-gadget.so")


with open(get_asset_path("attrib.json"), "r") as f:
    ATTRIB_IDX_DATA = json.loads(f.read())

if __name__ == "__main__":
    main()
