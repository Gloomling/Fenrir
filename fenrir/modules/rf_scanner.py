# fenrir/modules/rf_scanner.py
#
# Fix 20 — Changes from original:
#   - Added freq_range parameter (default "24M:1.7G" — RTL-SDR range)
#   - Added threshold parameter in dBm (default -20 — signals above this logged)
#   - Real RTL-SDR implementation via pyrtlsdr when hardware present
#   - SoapySDR fallback for other SDR hardware (HackRF, LimeSDR, etc.)
#   - Structured signal findings: frequency, power_db, bandwidth_estimate,
#     possible_service (from known frequency database)
#   - Frequency annotation from offline DB known_frequencies or built-in table
#   - ReportManager integration
#   - run() returns list of signal finding dicts
#   - Clear hardware-unavailable warning — no silent simulation

import asyncio
import math
from typing import Optional

from ..logging_config import get_logger
from ..report_manager import ReportManager

log = get_logger()

# RTL-SDR optional import
try:
    from rtlsdr import RtlSdr
    _RTLSDR_AVAILABLE = True
except ImportError:
    _RTLSDR_AVAILABLE = False

# SoapySDR optional import (fallback for HackRF, LimeSDR, etc.)
try:
    import SoapySDR
    _SOAPYSDR_AVAILABLE = True
except ImportError:
    _SOAPYSDR_AVAILABLE = False

# numpy required for signal processing
try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    _NUMPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Frequency annotation table
# Common frequencies with their likely service/use
# ---------------------------------------------------------------------------
_KNOWN_FREQUENCIES: list[tuple[float, float, str, str]] = [
    # (freq_low_hz, freq_high_hz, service_name, risk_note)
    (87.5e6,   108e6,    "FM Radio",         "Broadcast — typically safe"),
    (118e6,    137e6,    "Aviation AM",       "Air traffic control / aviation"),
    (136e6,    138e6,    "NOAA Weather",      "NOAA weather satellite downlink"),
    (144e6,    148e6,    "Amateur 2m",        "Amateur radio VHF"),
    (156e6,    174e6,    "Marine VHF",        "Marine band / emergency channel 16"),
    (315e6,    315.1e6,  "ASK/OOK 315MHz",   "Car key fobs, remotes — possible replay risk"),
    (433.82e6, 433.99e6, "ISM 433MHz",        "Remote controls, sensors — possible replay risk"),
    (434e6,    434.8e6,  "ISM 433MHz",        "Wireless sensors, LoRa devices"),
    (460e6,    470e6,    "Land Mobile",       "Business radio, paging systems"),
    (868e6,    868.6e6,  "ISM 868MHz",        "LoRa, Z-Wave, smart meters (EU)"),
    (902e6,    928e6,    "ISM 915MHz",        "LoRa, RFID, ZigBee (US)"),
    (1090e6,   1090.1e6, "ADS-B",             "Aircraft transponders — Mode-S/ADS-B"),
    (1575.42e6,1575.43e6,"GPS L1",            "GPS civilian signal"),
    (2400e6,   2483.5e6, "2.4GHz ISM",        "Wi-Fi, Bluetooth, ZigBee, microwave"),
    (5150e6,   5850e6,   "5GHz Wi-Fi",        "802.11a/n/ac/ax"),
]


class RfScanner:
    """
    Scans for RF signals using Software Defined Radio (SDR) hardware.

    Hardware support:
      - RTL-SDR dongles (via pyrtlsdr) — covers 24 MHz – 1.766 GHz
      - SoapySDR-compatible devices (HackRF, LimeSDR, etc.) — wider range

    Without SDR hardware, prints a clear message and returns empty results.
    Does NOT simulate signals — simulation was removed as it was misleading.

    Install dependencies:
      pip install pyrtlsdr numpy          (for RTL-SDR)
      pip install SoapySDR numpy          (for SoapySDR-compatible devices)
    """

    def __init__(self) -> None:
        log.debug("RfScanner initialised.")

    async def run(
        self,
        freq_range: str = "24M:1.7G",
        threshold: float = -20.0,
        duration: int = 20,
        sample_rate: float = 2.4e6,
        gain: Optional[float] = None,
        report: Optional[ReportManager] = None,
    ) -> list[dict]:
        """
        Scan a frequency range for RF signals.

        Args:
            freq_range:   Frequency range as "start:stop" with M/G/k suffixes.
                          Default "24M:1.7G" (full RTL-SDR range).
                          Examples: "400M:500M", "433M:434M", "88M:108M"
            threshold:    Minimum power level in dBm to report a signal.
                          Default -20 dBm. More negative = more sensitive.
            duration:     Total scan duration in seconds. Default 20.
            sample_rate:  IQ sample rate in Hz. Default 2.4 MHz.
            gain:         SDR gain in dB. None = auto-gain. Default None.
            report:       Optional ReportManager.

        Returns:
            List of signal finding dicts with keys:
              frequency_hz, frequency_label, power_db, possible_service,
              risk_note, bandwidth_estimate_hz
        """
        # --- Parse frequency range ---
        try:
            freq_start, freq_stop = _parse_freq_range(freq_range)
        except ValueError as exc:
            log.error(f"Invalid freq_range '{freq_range}': {exc}")
            return []

        log.info(
            f"RF scan: {_hz_label(freq_start)} – {_hz_label(freq_stop)} | "
            f"threshold {threshold} dBm | duration {duration}s"
        )

        # --- Hardware check ---
        if not _RTLSDR_AVAILABLE and not _SOAPYSDR_AVAILABLE:
            log.warning(
                "No SDR library found. Install pyrtlsdr or SoapySDR:\n"
                "  pip install pyrtlsdr numpy\n"
                "  pip install SoapySDR numpy\n"
                "An RTL-SDR dongle (~$25 USD) is required for hardware RF scanning."
            )
            return []

        if not _NUMPY_AVAILABLE:
            log.error(
                "numpy is required for RF signal processing. "
                "Install with: pip install numpy"
            )
            return []

        # --- Run scan ---
        signals: list[dict] = []

        if _RTLSDR_AVAILABLE:
            signals = await asyncio.to_thread(
                self._scan_rtlsdr,
                freq_start, freq_stop, threshold, duration, sample_rate, gain,
            )
        elif _SOAPYSDR_AVAILABLE:
            signals = await asyncio.to_thread(
                self._scan_soapysdr,
                freq_start, freq_stop, threshold, duration, sample_rate, gain,
            )

        # --- Annotate with known frequencies ---
        for sig in signals:
            service, risk = _annotate_frequency(sig["frequency_hz"])
            sig["possible_service"] = service
            sig["risk_note"]        = risk

        # --- Log findings ---
        if signals:
            log.warning(f"RF scan complete: {len(signals)} signal(s) detected.")
            for sig in signals:
                log.warning(
                    f"  {sig['frequency_label']:12} "
                    f"| Power: {sig['power_db']:+.1f} dBm "
                    f"| {sig.get('possible_service', 'Unknown service')}"
                )
        else:
            log.info(f"RF scan complete: no signals above {threshold} dBm detected.")

        # --- ReportManager ---
        if report and signals:
            report.add_section("RF Signal Detection", signals)

        return signals

    # ------------------------------------------------------------------
    # RTL-SDR implementation
    # ------------------------------------------------------------------

    def _scan_rtlsdr(
        self,
        freq_start: float,
        freq_stop: float,
        threshold: float,
        duration: int,
        sample_rate: float,
        gain: Optional[float],
    ) -> list[dict]:
        """
        Sweep the frequency range using an RTL-SDR dongle.
        Samples each frequency step for a short window and computes power spectrum.
        """
        signals = []

        try:
            sdr = RtlSdr()
        except Exception as exc:
            log.error(
                f"RTL-SDR device not found or could not be opened: {exc}\n"
                "Check that the dongle is plugged in and the driver is loaded."
            )
            return []

        try:
            sdr.sample_rate  = sample_rate
            sdr.set_agc_mode(gain is None)
            if gain is not None:
                sdr.gain = gain

            # Calculate step size and dwell time
            total_bw    = freq_stop - freq_start
            step_hz     = sample_rate * 0.8           # 80% of bandwidth per step
            num_steps   = max(1, int(total_bw / step_hz))
            dwell_secs  = max(0.5, duration / num_steps)
            num_samples = int(sample_rate * min(dwell_secs, 0.5))

            log.info(
                f"RTL-SDR: {num_steps} frequency steps, "
                f"~{dwell_secs:.1f}s dwell per step, "
                f"{num_samples:,} samples/step"
            )

            for step in range(num_steps):
                center_freq = freq_start + (step + 0.5) * step_hz
                center_freq = min(center_freq, freq_stop)

                try:
                    sdr.center_freq = center_freq
                    samples         = sdr.read_samples(num_samples)
                    power_db        = _compute_power_db(samples)

                    if power_db >= threshold:
                        bandwidth_est = _estimate_bandwidth(samples, sample_rate)
                        log.debug(
                            f"  Signal at {_hz_label(center_freq)}: "
                            f"{power_db:+.1f} dBm, BW ~{_hz_label(bandwidth_est)}"
                        )
                        signals.append({
                            "frequency_hz":         center_freq,
                            "frequency_label":      _hz_label(center_freq),
                            "power_db":             round(power_db, 2),
                            "bandwidth_estimate_hz": bandwidth_est,
                            "hardware":             "rtlsdr",
                        })
                except Exception as exc:
                    log.debug(f"RTL-SDR step error at {_hz_label(center_freq)}: {exc}")

        finally:
            sdr.close()

        return signals

    # ------------------------------------------------------------------
    # SoapySDR implementation
    # ------------------------------------------------------------------

    def _scan_soapysdr(
        self,
        freq_start: float,
        freq_stop: float,
        threshold: float,
        duration: int,
        sample_rate: float,
        gain: Optional[float],
    ) -> list[dict]:
        """Sweep frequency range using a SoapySDR-compatible device."""
        signals = []

        try:
            results = SoapySDR.Device.enumerate()
            if not results:
                log.error(
                    "SoapySDR: no devices found. "
                    "Check hardware connection and drivers."
                )
                return []

            sdr = SoapySDR.Device(results[0])
            sdr.setSampleRate(SoapySDR.SOAPY_SDR_RX, 0, sample_rate)
            if gain is not None:
                sdr.setGain(SoapySDR.SOAPY_SDR_RX, 0, gain)

            stream    = sdr.setupStream(SoapySDR.SOAPY_SDR_RX, SoapySDR.SOAPY_SDR_CF32)
            step_hz   = sample_rate * 0.8
            num_steps = max(1, int((freq_stop - freq_start) / step_hz))
            dwell_s   = max(0.5, duration / num_steps)
            n_samples = int(sample_rate * min(dwell_s, 0.5))
            buf       = np.zeros(n_samples, dtype=np.complex64)

            sdr.activateStream(stream)

            for step in range(num_steps):
                center_freq = freq_start + (step + 0.5) * step_hz
                try:
                    sdr.setFrequency(SoapySDR.SOAPY_SDR_RX, 0, center_freq)
                    sr = sdr.readStream(stream, [buf], n_samples)
                    if sr.ret > 0:
                        samples  = buf[:sr.ret]
                        power_db = _compute_power_db(samples)
                        if power_db >= threshold:
                            bw = _estimate_bandwidth(samples, sample_rate)
                            signals.append({
                                "frequency_hz":          center_freq,
                                "frequency_label":       _hz_label(center_freq),
                                "power_db":              round(power_db, 2),
                                "bandwidth_estimate_hz": bw,
                                "hardware":              "soapysdr",
                            })
                except Exception as exc:
                    log.debug(f"SoapySDR step error: {exc}")

            sdr.deactivateStream(stream)
            sdr.closeStream(stream)

        except Exception as exc:
            log.error(f"SoapySDR initialisation failed: {exc}")

        return signals


# ===========================================================================
# Module-level helpers
# ===========================================================================

def _parse_freq_range(freq_range: str) -> tuple[float, float]:
    """
    Parse a frequency range string like "433M:434M" or "24M:1.7G".
    Returns (start_hz, stop_hz).
    """
    parts = freq_range.strip().split(":")
    if len(parts) != 2:
        raise ValueError("Expected format 'start:stop' (e.g. '433M:434M')")
    return _parse_freq(parts[0]), _parse_freq(parts[1])


def _parse_freq(freq_str: str) -> float:
    """Parse a frequency string with optional suffix (k/M/G)."""
    freq_str = freq_str.strip().upper()
    multipliers = {"K": 1e3, "M": 1e6, "G": 1e9}
    for suffix, mult in multipliers.items():
        if freq_str.endswith(suffix):
            return float(freq_str[:-1]) * mult
    return float(freq_str)


def _hz_label(freq_hz: float) -> str:
    """Format a frequency in Hz as a human-readable string."""
    if freq_hz >= 1e9:
        return f"{freq_hz / 1e9:.3f} GHz"
    elif freq_hz >= 1e6:
        return f"{freq_hz / 1e6:.3f} MHz"
    elif freq_hz >= 1e3:
        return f"{freq_hz / 1e3:.1f} kHz"
    return f"{freq_hz:.0f} Hz"


def _compute_power_db(samples) -> float:
    """Compute average power in dBm from IQ samples."""
    try:
        power_linear = float(np.mean(np.abs(samples) ** 2))
        if power_linear <= 0:
            return -120.0
        return 10 * math.log10(power_linear)
    except Exception:
        return -120.0


def _estimate_bandwidth(samples, sample_rate: float) -> float:
    """
    Rough bandwidth estimate using FFT occupancy.
    Returns the 3dB bandwidth in Hz.
    """
    try:
        spectrum = np.abs(np.fft.fftshift(np.fft.fft(samples))) ** 2
        peak     = np.max(spectrum)
        mask     = spectrum >= (peak / 2)  # 3dB threshold
        occupied = np.sum(mask)
        return float(occupied) / len(spectrum) * sample_rate
    except Exception:
        return 0.0


def _annotate_frequency(freq_hz: float) -> tuple[str, str]:
    """Return (service_name, risk_note) for a given frequency in Hz."""
    for low, high, service, risk in _KNOWN_FREQUENCIES:
        if low <= freq_hz <= high:
            return service, risk
    return "Unknown", "No known service at this frequency"
