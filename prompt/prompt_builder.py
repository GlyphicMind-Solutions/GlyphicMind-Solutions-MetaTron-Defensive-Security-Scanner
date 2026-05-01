# MetaTron/prompt/prompt_builder.py
# MetaTron Prompt Builder (model-family aware)
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.




# ====================================
# PROMPT BUILDER CLASS
# ====================================
class PromptBuilder:
    """
    PromptBuilder for MetaTron.

    Responsibilities:
    - Build model-family-aware prompts for defensive security analysis.
    - Enforce: defensive-only, internal networks only, no offensive content.
    - Apply model-family templates (gpt, mistral, llama, qwen, deepseek, phi).
    - Produce a clean, consistent prompt for LLMEngine.
    """
    # -------------------------
    # Build Prompt
    # -------------------------
    def build_prompt(self, target: str, raw_scan: str, model_key: str) -> str:
        family = self._infer_family(model_key)

        if family == "gpt":
            return self._build_gpt_prompt(target, raw_scan)
        if family == "mistral":
            return self._build_mistral_prompt(target, raw_scan)
        if family == "qwen":
            return self._build_qwen_prompt(target, raw_scan)
        if family == "deepseek":
            return self._build_deepseek_prompt(target, raw_scan)
        if family == "phi":
            return self._build_phi_prompt(target, raw_scan)

        # default → llama-style
        return self._build_llama_prompt(target, raw_scan)

    # -------------------------
    # Infer family (model)
    # -------------------------
    def _infer_family(self, model_key: str) -> str:
        k = model_key.lower()

        if "gpt" in k:
            return "gpt"
        if "mistral" in k:
            return "mistral"
        if "qwen" in k:
            return "qwen"
        if "deepseek" in k:
            return "deepseek"
        if "phi" in k:
            return "phi"
        if "llama" in k or "hermes" in k:
            return "llama"

        return "llama"

    # -------------------------
    # Core defensive system prompt
    # -------------------------
    def _core(self, target: str, raw_scan: str) -> str:
        return f"""
You are MetaTron, a defensive security analysis system.
You ONLY analyze authorized internal networks.
You NEVER provide offensive or unauthorized exploitation steps.
You focus on detection, risk assessment, mitigation, and hardening.

TARGET: {target}

RECON DATA:
{raw_scan}

Provide:
- vulnerabilities
- severity
- ports/services
- descriptions
- fixes
- internal validation exploits (if applicable)
- final risk level
- summary

End with FIN~.
""".strip()

    # -------------------------
    # GPT template
    # -------------------------
    def _build_gpt_prompt(self, target: str, raw_scan: str) -> str:
        core = self._core(target, raw_scan)
        return (
            "<|start|>system<|message|>\n"
            f"{core}\n"
            "<|end|>\n\n"
            "<|start|>assistant<|message|>\n"
        )

    # -------------------------
    # Mistral template
    # -------------------------
    def _build_mistral_prompt(self, target: str, raw_scan: str) -> str:
        core = self._core(target, raw_scan)
        return (
            "<s>[INST]\n"
            f"{core}\n"
            "[/INST]\n"
        )

    # -------------------------
    # Qwen template
    # -------------------------
    def _build_qwen_prompt(self, target: str, raw_scan: str) -> str:
        core = self._core(target, raw_scan)
        return (
            "<|im_start|>system\n"
            f"{core}\n"
            "<|im_end|>\n"
            "<|im_start|>assistant\n"
        )

    # -------------------------
    # DeepSeek template
    # -------------------------
    def _build_deepseek_prompt(self, target: str, raw_scan: str) -> str:
        core = self._core(target, raw_scan)
        return (
            "<|begin_of_text|><|system|>\n"
            f"{core}\n"
            "<|end|>\n"
            "<|assistant|>\n"
        )

    # -------------------------
    # Phi template
    # -------------------------
    def _build_phi_prompt(self, target: str, raw_scan: str) -> str:
        core = self._core(target, raw_scan)
        return (
            "### System\n"
            f"{core}\n\n"
            "### Assistant\n"
        )

    # -------------------------
    # Llama / default template
    # -------------------------
    def _build_llama_prompt(self, target: str, raw_scan: str) -> str:
        core = self._core(target, raw_scan)
        return (
            "<|im_start|>system\n"
            f"{core}\n"
            "<|im_end|>\n"
            "<|im_start|>assistant\n"
        )

