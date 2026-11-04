(() => {
  const search = [
    document.querySelector(".quick-search input"),
    document.querySelector(".hero-search input"),
  ].find((element) => element && element.offsetParent !== null);

  document.addEventListener("keydown", (event) => {
    const tag = (event.target.tagName || "").toLowerCase();
    if (event.key === "/" && !["input", "textarea", "select"].includes(tag)) {
      event.preventDefault();
      if (search) search.focus();
    }
    if (event.key === "Escape" && document.activeElement && document.activeElement.type === "search") {
      document.activeElement.blur();
    }
  });

  document.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;

    try {
      await navigator.clipboard.writeText(button.dataset.copy);
      const old = button.textContent;
      button.textContent = "copied";
      setTimeout(() => {
        button.textContent = old;
      }, 1200);
    } catch (error) {
      // clipboard bloqueado pelo navegador, nao tem muito o que fazer
    }
  });
})();
