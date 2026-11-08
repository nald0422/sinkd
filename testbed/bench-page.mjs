// The benchmark page: a generated news front page, the same on every run.

/** A news-style page: ~2,000 elements with the class names such pages use. */
export function benchPage(count = 120) {
  let seed = 7;
  const rand = (n) => {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    return seed % n;
  };
  const words = "market city weather report council school river music garden local".split(" ");
  const text = (n) => Array.from({ length: n }, () => words[rand(words.length)]).join(" ");
  const cards = Array.from(
    { length: count },
    (_, i) => `<article class="card story-${i % 7} grid-item" id="story-${i}">
  <a class="card__link" href="/story/${i}"><img class="card__thumb lazy" src="/img/${i}.gif" width="120" height="80" alt=""></a>
  <h2 class="card__title headline">${text(6)}</h2>
  <p class="card__meta byline"><span class="author">${text(2)}</span> <time class="date">today</time></p>
  <p class="card__summary">${text(30)}</p>
  <ul class="tags">${Array.from({ length: 3 }, () => `<li class="tag tag-${words[rand(10)]}">${words[rand(10)]}</li>`).join("")}</ul>
</article>`,
  ).join("\n");
  const widgets = Array.from(
    { length: 12 },
    (_, i) =>
      `<aside class="widget widget-${i} sidebar-box"><h3 class="widget__title">${text(3)}</h3><p>${text(20)}</p></aside>`,
  ).join("\n");
  return `<!doctype html><meta charset="utf-8"><title>Bench</title>
<style>
body { font: 16px/1.4 system-ui, sans-serif; margin: 0; }
.site-header { background: #123; color: #fff; padding: 12px; }
.layout { display: grid; grid-template-columns: 3fr 1fr; gap: 16px; padding: 16px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
.card { border: 1px solid #ddd; padding: 8px; } .tag { display: inline; margin-right: 6px; }
</style>
<header class="site-header" id="top"><nav class="main-nav"><a class="nav-link" href="/">Home</a></nav></header>
<div class="layout"><main class="grid" id="main">${cards}</main><div class="sidebar" id="sidebar">${widgets}</div></div>
<footer class="site-footer">${text(40)}</footer>`;
}
