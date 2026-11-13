// Admin navigation bar, shown on every page only while an admin is logged in.
// Anonymous visitors never see it. Hiding it is a UI choice, not a security measure:
// the admin API checks the session on every request regardless.
(() => {
  const LINKS = [
    { label: "Upload", href: "/" },
    { label: "Stats", href: "/stats" },
    { label: "Files", href: "/admin#files" },
    { label: "Admin", href: "/admin" },
  ];

  // "/admin#files" is current only on that tab; "/admin" on every other admin tab.
  function isCurrent(href) {
    const [path, hash] = href.split("#");
    if (window.location.pathname !== path) return false;
    const currentHash = window.location.hash.slice(1);
    if (hash) return currentHash === hash;
    return !LINKS.some((link) => link.href === `${path}#${currentHash}`);
  }

  function markCurrent(links) {
    for (const link of links.querySelectorAll("a")) {
      if (isCurrent(link.getAttribute("href"))) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    }
  }

  function build(username) {
    const nav = document.createElement("nav");
    nav.className = "admin-nav";
    nav.setAttribute("aria-label", "Admin navigation");

    const user = document.createElement("span");
    user.className = "admin-nav-user";
    const name = document.createElement("strong");
    name.textContent = username; // text node: never parsed as HTML
    user.append("Admin: ", name);

    const links = document.createElement("div");
    links.className = "admin-nav-links";
    for (const { label, href } of LINKS) {
      const link = document.createElement("a");
      link.href = href;
      link.textContent = label;
      links.append(link);
    }
    markCurrent(links);

    const logout = document.createElement("button");
    logout.type = "button";
    logout.textContent = "Log out";
    logout.addEventListener("click", async () => {
      await fetch("/api/admin/logout", { method: "POST" });
      window.location.reload();
    });
    links.append(logout);

    nav.append(user, links);
    return nav;
  }

  // Only the latest refresh may touch the DOM, so overlapping calls never add two bars.
  let generation = 0;

  async function refresh() {
    const mine = ++generation;
    let status = null;
    try {
      const response = await fetch("/api/admin/status", { cache: "no-store" });
      if (response.ok) {
        status = await response.json();
      }
    } catch {
      // Network error: behave as logged out.
    }
    if (mine !== generation) {
      return;
    }

    document.querySelector(".admin-nav")?.remove();
    if (status && status.authenticated) {
      // Above the scroll area, like the footer below it, so it never scrolls away.
      const scrollArea = document.querySelector(".page-scroll");
      document.body.insertBefore(build(status.username), scrollArea);
    }
  }

  // Registered once: the bar is rebuilt on every refresh, so look it up each time.
  window.addEventListener("hashchange", () => {
    const links = document.querySelector(".admin-nav-links");
    if (links) markCurrent(links);
  });

  // The admin page calls this after login, logout or an expired session.
  window.bhsNav = { refresh };
  refresh();
})();
