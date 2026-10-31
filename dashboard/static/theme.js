/* Apply the saved theme before paint. The requested default is dark. */
(() => {
 let saved='dark';try{saved=localStorage.getItem('sweetberry-theme')||'dark';}catch{}
 document.documentElement.dataset.theme=saved==='light'?'light':'dark';
 function label(){const button=document.getElementById('theme-toggle');if(!button)return;const dark=document.documentElement.dataset.theme==='dark';button.innerHTML='<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">'+(dark?'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M5 19l1.5-1.5M17.5 6.5L19 5"/>':'<path d="M20 15A9 9 0 0 1 9 4a9 9 0 1 0 11 11Z"/>')+'</svg><span>'+(dark?'Light theme':'Dark theme')+'</span>';button.setAttribute('aria-label',dark?'Switch to light theme':'Switch to dark theme');button.setAttribute('aria-pressed',String(dark));document.querySelector('meta[name=theme-color]')?.setAttribute('content',dark?'#160e22':'#f3f0f8');}
 document.addEventListener('DOMContentLoaded',()=>{label();document.getElementById('theme-toggle')?.addEventListener('click',()=>{const next=document.documentElement.dataset.theme==='dark'?'light':'dark';document.documentElement.dataset.theme=next;try{localStorage.setItem('sweetberry-theme',next);}catch{}label();});});
})();
