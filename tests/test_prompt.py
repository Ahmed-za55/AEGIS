from aegis.llm.nebius_client import NebiusClient


class _Fake:
    def __init__(self):
        self.chat = self
        self.completions = self

    def create(self, **kwargs):
        self.messages = kwargs["messages"]

        class M:
            content = "```python\nprint(1)\n```"

        class C:
            message = M()

        class R:
            choices = [C()]

        return R()


def test_feedback_prompt_discourages_dumping_the_allowed_module_list():
    fake = _Fake()
    NebiusClient(model="m", client=fake).propose_code(
        "task", feedback=["import of 'os' is not allowed"])
    text = fake.messages[1]["content"]
    assert "import of 'os' is not allowed" in text
    assert "Import a module only if you use it" in text
    assert "still solves the task" in text
