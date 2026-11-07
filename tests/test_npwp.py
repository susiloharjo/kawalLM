from kawallm import synthetic
from kawallm.pii import validate_npwp
from kawallm.pii.npwp import find_npwp, luhn_valid


def test_luhn():
    assert luhn_valid("79927398713")
    assert not luhn_valid("79927398710")


def test_synthetic_npwp_valid_formatted_and_plain():
    for seed in range(100):
        f = synthetic.npwp(seed)
        assert validate_npwp(f)
        assert validate_npwp(synthetic.npwp(seed, formatted=False))
        assert validate_npwp("0" + synthetic.npwp(seed, formatted=False))  # 16-digit entity form


def test_bad_checksum_rejected():
    good = synthetic.npwp(1, formatted=False)
    bad = good[:8] + str((int(good[8]) + 1) % 10) + good[9:]
    assert not validate_npwp(bad)


def test_16_digit_non_zero_prefix_is_nik_territory():
    assert not validate_npwp("1" + synthetic.npwp(1, formatted=False))


def test_wrong_length():
    assert not validate_npwp("12345")


def test_find_formatted_without_keyword():
    f = synthetic.npwp(3)
    assert [m.text for m in find_npwp(f"Nomor {f} terdaftar")] == [f]


def test_plain_requires_keyword():
    p = synthetic.npwp(4, formatted=False)
    assert find_npwp(f"kode {p}") == []
    assert [m.text for m in find_npwp(f"NPWP perusahaan {p}")] == [p]
