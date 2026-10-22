import tempfile
import unittest
from pathlib import Path

from agent_security.envfile import load_env_file, parse_env_file


class EnvFileTests(unittest.TestCase):
    def test_parsing(self):
        text = "\n".join(
            [
                "# comment",
                "",
                "PLAIN=value",
                "export EXPORTED=1",
                'DOUBLE="with spaces # not a comment"',
                "SINGLE='x=y'",
                "INLINE=abc # trailing comment",
                "EMPTY=",
                "not a setting",
                "1BAD=x",
            ]
        )
        self.assertEqual(
            parse_env_file(text),
            {
                "PLAIN": "value",
                "EXPORTED": "1",
                "DOUBLE": "with spaces # not a comment",
                "SINGLE": "x=y",
                "INLINE": "abc",
                "EMPTY": "",
            },
        )

    def test_shell_variables_win_and_empty_values_are_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("A=from-file\nB=from-file\nC=\n", encoding="utf-8")
            env = {"A": "from-shell"}
            self.assertEqual(load_env_file(path, env), ["B"])
            self.assertEqual(env, {"A": "from-shell", "B": "from-file"})
            self.assertEqual(load_env_file(Path(directory) / "missing", env), [])


if __name__ == "__main__":
    unittest.main()
