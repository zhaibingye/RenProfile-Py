import unittest

from renprofile.errors import RenProfileError
from renprofile.paths import PathRewriter, normalize, validate_pair


class PathTests(unittest.TestCase):
    def setUp(self):
        self.rewrite = PathRewriter(r"C:\Users\Old", r"C:\Users\New$1")

    def test_literal_unicode_and_case(self):
        rewrite = PathRewriter(r"C:\Users\旧用户", r"C:\Users\新$1用户")
        self.assertEqual(rewrite(r'"c:\users\旧用户\桌面"'), r'"C:\Users\新$1用户\桌面"')

    def test_no_similar_prefix_or_suffix_replacement(self):
        for value in (r"C:\Users\Older", r"C:\Users\Old.bak", r"C:\Users\Old User", r"XC:\Users\Old",
                      r"D:\C:\Users\Old", r"C:\Users\Old-extra"):
            with self.subTest(value=value):
                self.assertEqual(self.rewrite(value), value)

    def test_default_multi_expand_and_non_string_values(self):
        self.assertEqual(self.rewrite.data([r"C:\Users\Old", "%USERPROFILE%\\Temp"], 7),
                         [r"C:\Users\New$1", "%USERPROFILE%\\Temp"])
        self.assertEqual(self.rewrite.data("%USERPROFILE%\\Temp", 2), "%USERPROFILE%\\Temp")
        self.assertEqual(self.rewrite.data(b"C:\\Users\\Old", 3), b"C:\\Users\\Old")
        self.assertEqual(self.rewrite.data(42, 4), 42)

    def test_variants(self):
        cases = {r"C:/Users/Old/App": r"C:/Users/New$1/App",
                 r"C:\\Users\\Old\\App": r"C:\\Users\\New$1\\App",
                 r"C:%5CUsers%5COld%5CApp": r"C:%5CUsers%5CNew$1%5CApp",
                 r"C%3A%5CUsers%5COld%5CApp": r"C%3A%5CUsers%5CNew%241%5CApp",
                 r"file:///C:/Users/Old/App": r"file:///C:/Users/New%241/App",
                 r"\\?\C:\Users\Old\App": r"\\?\C:\Users\New$1\App"}
        for before, after in cases.items():
            with self.subTest(before=before):
                self.assertEqual(self.rewrite(before), after)

    def test_empty_short_path_never_matches_everything(self):
        self.assertEqual(self.rewrite("anything without a path"), "anything without a path")

    def test_short_path(self):
        rewrite = PathRewriter(r"C:\Users\Old Name", r"C:\Users\New", r"C:\Users\OLDNAM~1")
        self.assertEqual(rewrite(r"C:\Users\OLDNAM~1\App"), r"C:\Users\New\App")

    def test_unicode_ignorecase_extra_characters_do_not_crash(self):
        rewrite = PathRewriter(r"C:\Users\I", r"C:\Users\New")
        self.assertEqual(rewrite("C:\\Users\\ı\\App"), "C:\\Users\\ı\\App")

    def test_validation(self):
        invalid = [(r"C:\Users\Old", r"D:\Users\New"), (r"C:\Users\Old", r"C:\Users\old"),
                   (r"C:\Users\Old", "C:\\Users\\New "), (r"C:\Users\Old", r"C:\Users\CON.txt"),
                   (r"C:\Users\Old", r"C:\Users\..\New"), (r"C:\Users\Old", r"C:\Users\New:stream"),
                   (r"C:\Users\Old", r"\\server\share\New"), (r"C:\Users\Old", r"relative\New")]
        for pair in invalid:
            with self.subTest(pair=pair), self.assertRaises(RenProfileError):
                validate_pair(*pair)
        self.assertEqual(normalize("C:/Users/New/"), r"C:\Users\New")


if __name__ == "__main__":
    unittest.main()
