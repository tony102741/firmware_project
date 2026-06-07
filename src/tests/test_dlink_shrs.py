import unittest

from src import pipeline


class DlinkShrSTests(unittest.TestCase):
    def test_dirx3260_model_key_accepts_hyphenless_filename(self) -> None:
        self.assertEqual(
            pipeline._dlink_shrs_model_key("DIRX3260A1_FW101B05.bin"),
            "dir-x3260",
        )

    def test_dirx3260_vendor_key_derivation(self) -> None:
        self.assertEqual(
            pipeline._dlink_shrs_vendor_key_hex("dir-x3260"),
            "7274392d34255e2b4d212964363d6d7e",
        )


if __name__ == "__main__":
    unittest.main()
