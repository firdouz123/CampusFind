document.addEventListener("DOMContentLoaded", () => {
  const navToggle = document.querySelector(".mobile-nav-toggle");
  const navigation = document.querySelector(".primary-nav");

  if (navToggle && navigation) {
    navToggle.addEventListener("click", () => {
      const isOpen = navToggle.getAttribute("aria-expanded") === "true";
      navToggle.setAttribute("aria-expanded", String(!isOpen));
      navigation.classList.toggle("nav-open", !isOpen);
    });
  }

  document.querySelectorAll(".flash-close").forEach((button) => {
    button.addEventListener("click", () => button.closest(".flash")?.remove());
  });

  document.querySelectorAll("[data-char-count]").forEach((counter) => {
    const field = document.getElementById(counter.dataset.charCount);
    if (!field) return;
    const updateCount = () => {
      counter.textContent = String(field.value.length);
    };
    field.addEventListener("input", updateCount);
    updateCount();
  });

  const imageInput = document.querySelector("#image");
  const fileLabel = document.querySelector("[data-file-label]");
  if (imageInput && fileLabel) {
    imageInput.addEventListener("change", () => {
      fileLabel.textContent = imageInput.files?.[0]?.name || "Choose an image";
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  const formDate = document.querySelector("#item_date");
  if (formDate && !formDate.value) {
    const today = new Date();
    const localDate = new Date(today.getTime() - today.getTimezoneOffset() * 60_000)
      .toISOString()
      .slice(0, 10);
    formDate.value = localDate;
    formDate.max = localDate;
  }
});
