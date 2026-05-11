import os
import sys
from pathlib import Path

# =====================================================
# Xiaomi Secret Album Recovery Tool (Offline)
# =====================================================
# Tool ini mencoba memulihkan file .lsa dan .lsav
# secara lokal tanpa upload internet.
#
# Cara pakai:
# 1. Simpan file ini sebagai:
#    recover_lsa.py
#
# 2. Jalankan:
#    python recover_lsa.py "D:\\secretAlbum"
#
# Contoh:
#    python recover_lsa.py "C:\\Users\\Nama\\Pictures\\secretAlbum"
#
# Hasil recovery akan masuk ke folder:
# recovered
# =====================================================

# =====================================================
# MODE ANALISA TAMBAHAN
# =====================================================
# Tool ini sekarang memiliki:
# - scan signature file
# - brute XOR sederhana
# - logging detail
# - validasi hasil recovery
# =====================================================

JPEG_HEADERS = [
    bytes.fromhex('FFD8FFDB'),
    bytes.fromhex('FFD8FFE0'),
    bytes.fromhex('FFD8FFE1'),
]

MP4_HEADER = b'ftyp'


# =====================================================
# Utility
# =====================================================
def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


# =====================================================
# XOR detector sederhana
# =====================================================
def try_single_byte_xor(data, expected_headers):
    for key in range(256):
        decoded = bytes([b ^ key for b in data[:32]])

        for header in expected_headers:
            if decoded.startswith(header):
                return key

    return None


# =====================================================
# Validasi signature hasil recovery
# =====================================================
def is_valid_jpeg(data):
    return data.startswith(b'ÿØÿ')


def is_valid_mp4(data):
    return b'ftyp' in data[:64]


def analyze_file_signature(data):
    signatures = {
        b'ÿØÿ': 'JPEG',
        b'PNG': 'PNG',
        b'ftyp': 'MP4',
        b'RIFF': 'AVI/WAV',
    }

    for sig, name in signatures.items():
        if sig in data[:128]:
            return name

    return 'UNKNOWN'


# =====================================================
# Recovery JPG
# =====================================================
def recover_lsa(file_path, out_dir):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        key = try_single_byte_xor(data, JPEG_HEADERS)

        if key is None:
            print(f'[!] Gagal recover JPG: {file_path.name}')
            return False

        recovered = bytes([b ^ key for b in data])

        detected = analyze_file_signature(recovered)

        if not is_valid_jpeg(recovered):
            print(f'[!] Signature tidak valid: {file_path.name} -> {detected}')
            return False

        out_file = os.path.join(out_dir, file_path.stem + '.jpg')

        with open(out_file, 'wb') as f:
            f.write(recovered)

        print(f'[OK] JPG recovered: {out_file}')
        print(f'[INFO] Signature: {detected}')
        return True

    except Exception as e:
        print(f'[ERROR] {file_path.name}: {e}')
        return False


# =====================================================
# Recovery MP4
# =====================================================
def recover_lsav(file_path, out_dir):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        found_key = None

        for key in range(256):
            decoded = bytes([b ^ key for b in data[:64]])

            if MP4_HEADER in decoded:
                found_key = key
                break

        if found_key is None:
            print(f'[!] Gagal recover MP4: {file_path.name}')
            return False

        recovered = bytes([b ^ found_key for b in data])

        detected = analyze_file_signature(recovered)

        if not is_valid_mp4(recovered):
            print(f'[!] Signature MP4 tidak valid: {file_path.name} -> {detected}')
            return False

        out_file = os.path.join(out_dir, file_path.stem + '.mp4')

        with open(out_file, 'wb') as f:
            f.write(recovered)

        print(f'[OK] MP4 recovered: {out_file}')
        print(f'[INFO] Signature: {detected}')
        return True

    except Exception as e:
        print(f'[ERROR] {file_path.name}: {e}')
        return False


# =====================================================
# Validasi folder
# =====================================================
def validate_folder(folder):
    if not folder:
        print('[!] Path folder kosong')
        return False

    if not os.path.exists(folder):
        print('[!] Folder tidak ditemukan')
        return False

    if not os.path.isdir(folder):
        print('[!] Path bukan folder')
        return False

    return True


# =====================================================
# Main
# =====================================================
def main():

    # =================================================
    # Hindari error input() pada environment tertentu
    # =================================================
    if len(sys.argv) >= 2:
        folder = sys.argv[1].strip().strip('"')
    else:
        print('=====================================================')
        print('Xiaomi Secret Album Recovery Tool')
        print('=====================================================')
        print('Cara penggunaan:')
        print('python recover_lsa.py "D:\\\\secretAlbum"')
        print('=====================================================')
        return

    if not validate_folder(folder):
        return

    out_dir = os.path.join(folder, 'recovered')
    ensure_dir(out_dir)

    total = 0
    success = 0

    print('\n[INFO] Memulai scan file...\n')

    for file_name in os.listdir(folder):
        file_path = Path(folder) / file_name

        if file_path.is_dir():
            continue

        suffix = file_path.suffix.lower()

        if suffix == '.lsa':
            total += 1
            if recover_lsa(file_path, out_dir):
                success += 1

        elif suffix == '.lsav':
            total += 1
            if recover_lsav(file_path, out_dir):
                success += 1

    print('\n=====================================================')
    print(f'Total file : {total}')
    print(f'Berhasil   : {success}')
    print(f'Gagal      : {total - success}')
    print('=====================================================')

    if total == 0:
        print('\n[!] Tidak ada file .lsa atau .lsav ditemukan')

    elif success == 0:
        print('\nKemungkinan file memakai enkripsi Xiaomi penuh.')
        print('Recovery terbaik biasanya memakai HP Xiaomi asli + akun Mi yang sama.')

    else:
        print('\n[OK] Recovery selesai')
        print(f'Hasil berada di: {out_dir}')


# =====================================================
# Test sederhana
# =====================================================
def run_tests():
    assert try_single_byte_xor(bytes([0xFF ^ 1, 0xD8 ^ 1, 0xFF ^ 1, 0xE0 ^ 1]), JPEG_HEADERS) == 1
    assert validate_folder('') is False


if __name__ == '__main__':
    run_tests()
    main()


# =====================================================
# STEP BY STEP PENGGUNAAN (WAJIB DIBACA)
# =====================================================
#
# PERSIAPAN:
# -----------------------------------------------------
# 1. Copy folder Xiaomi Secret Album ke PC:
#
#    MIUI/Gallery/cloud/secretAlbum
#
# 2. Jangan jalankan langsung dari HP.
#    Copy dulu ke HDD/SSD PC.
#
# 3. Pastikan ruang kosong cukup.
#    Karena hasil recovery akan membuat file baru.
#
# -----------------------------------------------------
# INSTALL PYTHON:
# -----------------------------------------------------
# 1. Download Python:
#    https://www.python.org/downloads/
#
# 2. Saat install:
#    CENTANG:
#    [x] Add Python to PATH
#
# 3. Setelah selesai buka CMD lalu cek:
#
#    python --version
#
# -----------------------------------------------------
# MENJALANKAN TOOL:
# -----------------------------------------------------
# 1. Simpan file ini sebagai:
#
#    recover_lsa.py
#
# 2. Buka CMD
#
# 3. Masuk ke folder script:
#
#    cd Desktop
#
# 4. Jalankan:
#
#    python recover_lsa.py "D:\secretAlbum"
#
#    Ganti lokasi folder sesuai milikmu.
#
# -----------------------------------------------------
# HASIL RECOVERY:
# -----------------------------------------------------
# Hasil otomatis berada di:
#
#    D:\secretAlbum\recovered
#
# Berisi:
# - JPG hasil recovery
# - MP4 hasil recovery
#
# -----------------------------------------------------
# MEMBUAT VERSI EXE:
# -----------------------------------------------------
# 1. Install pyinstaller:
#
#    python -m pip install pyinstaller
#
# 2. Build exe:
#
#    python -m PyInstaller --onefile recover_lsa.py
#
# 3. File exe berada di:
#
#    dist\recover_lsa.exe
#
# 4. Menjalankan exe:
#
#    recover_lsa.exe "D:\secretAlbum"
#
# -----------------------------------------------------
# TROUBLESHOOTING:
# -----------------------------------------------------
# 1. 'python is not recognized'
#    -> Python belum terinstall benar.
#
# 2. 'Folder tidak ditemukan'
#    -> Pastikan path folder benar.
#
# 3. Semua file gagal recovery
#    -> Kemungkinan Xiaomi memakai enkripsi penuh.
#       Recovery terbaik memakai HP Xiaomi asli
#       + akun Mi yang sama.
#
# =====================================================
# CARA MEMBUAT VERSI EXE
# =====================================================
# 1. Install pyinstaller:
#    pip install pyinstaller
#
# 2. Buat file exe:
#    pyinstaller --onefile recover_lsa.py
#
# 3. File exe akan berada di folder:
#    dist
#
#    Nama file:
#    recover_lsa.exe
#
# 4. Jalankan lewat CMD:
#
#    recover_lsa.exe "D:\\secretAlbum"
#
# =====================================================
