import unittest

from src.batch.batch_regression import classify_success_quality


class BatchQualityClassificationTests(unittest.TestCase):
    def test_general_mode_rootfs_path_is_rootfs_success(self) -> None:
        result = {
            "status": "SUCCESS",
            "analysis_mode": "general",
            "analysis_system_path": ".cache/build/foo/_nested_bar/_raw",
            "candidate_count": 3,
            "blob_candidate_count": 0,
        }

        self.assertEqual(classify_success_quality(result), "rootfs-success")

    def test_general_mode_blob_without_rootfs_marker_stays_blob_success(self) -> None:
        result = {
            "status": "SUCCESS",
            "analysis_mode": "general",
            "analysis_system_path": ".cache/build/foo",
            "candidate_count": 1,
            "blob_candidate_count": 1,
        }

        self.assertEqual(classify_success_quality(result), "blob-success")


if __name__ == "__main__":
    unittest.main()
