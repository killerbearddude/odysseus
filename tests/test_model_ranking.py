from __future__ import annotations

from services.cookbook_preflight import HardwareProfile, recommend_models


def test_low_vram_recommends_smaller_quantized_models():
    # Regression guard: limited VRAM should not recommend oversized defaults.
    recs = recommend_models(HardwareProfile(ram_bytes=16 * 1024**3, vram_bytes=6 * 1024**3, gpu_vendor="nvidia"))

    assert any("quantized" in rec.name or "quantized" in rec.reason.lower() for rec in recs)


def test_high_vram_allows_larger_models():
    # Regression guard: high-VRAM systems should be allowed larger local recommendations.
    recs = recommend_models(HardwareProfile(ram_bytes=64 * 1024**3, vram_bytes=24 * 1024**3, gpu_vendor="nvidia"))

    assert any("larger" in rec.name or rec.backend == "vLLM" for rec in recs)


def test_cpu_only_path_does_not_recommend_gpu_only_backend():
    # Regression guard: CPU-only operators should not be sent to GPU-only backends.
    recs = recommend_models(HardwareProfile(ram_bytes=16 * 1024**3, vram_bytes=None, gpu_vendor="none_detected"))

    assert all(not rec.gpu_required for rec in recs if rec.backend != "Hugging Face")
    assert any(rec.backend == "llama.cpp" for rec in recs)


def test_wsl_constraints_affect_recommendation():
    # Regression guard: WSL hosts need explicit networking/GPU caveats.
    recs = recommend_models(HardwareProfile(ram_bytes=16 * 1024**3, vram_bytes=None, wsl_detected=True))

    assert any("wsl" in rec.reason.lower() for rec in recs)


def test_offline_mode_avoids_remote_download_only_recommendations():
    # Regression guard: offline recommendations must not point at remote-download-only options.
    recs = recommend_models(HardwareProfile(ram_bytes=16 * 1024**3, offline_mode=True))

    assert all(not rec.remote_download_required for rec in recs)
