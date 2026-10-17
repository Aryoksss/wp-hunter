import tempfile
import unittest
from pathlib import Path

from wp_hunter.lock import StateBusy, lock_path, state_lock


class StateLockTests(unittest.TestCase):
    def test_lock_is_exclusive_within_a_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)

            def acquire() -> None:
                with state_lock(directory):
                    pass

            with state_lock(directory), self.assertRaises(StateBusy):
                acquire()
            # Released again after the block exits.
            acquire()

    def test_separate_directories_do_not_conflict(self):
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
            state_lock(Path(first)),
            state_lock(Path(second)),
        ):
            pass

    def test_lock_file_is_created_in_the_directory(self):
        with tempfile.TemporaryDirectory() as tmp, state_lock(Path(tmp)):
            self.assertTrue(lock_path(Path(tmp)).exists())


if __name__ == "__main__":
    unittest.main()
