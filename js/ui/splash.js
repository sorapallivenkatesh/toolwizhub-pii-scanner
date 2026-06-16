/* ui/splash.js — branded splash, once per tab session, click-to-skip. */
const KEY = "pii:splashed";

export function playSplash() {
  const splash = document.getElementById("splash");
  if (!splash) return;
  if (document.documentElement.classList.contains("no-splash")) { splash.remove(); return; }

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const hold = reduced ? 400 : 1700;
  const fade = reduced ? 150 : 600;

  let done = false;
  const dismiss = () => {
    if (done) return;
    done = true;
    try { sessionStorage.setItem(KEY, "1"); } catch (_) {}
    splash.classList.add("is-hiding");
    setTimeout(() => splash.remove(), fade);
  };
  splash.addEventListener("click", dismiss);
  setTimeout(dismiss, hold);
}
