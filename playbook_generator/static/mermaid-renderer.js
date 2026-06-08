import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';

mermaid.initialize({
    startOnLoad: false,
    theme: 'base',
    securityLevel: 'loose',
    flowchart: {
        curve: 'stepAfter',
        htmlLabels: true
    },
    themeVariables: {
        primaryColor: '#0d0d0d',
        primaryTextColor: '#e0e0e0',
        primaryBorderColor: '#00ff41',
        lineColor: '#00ff41',
        secondaryColor: '#1a1a1a',
        tertiaryColor: '#111',
        fontFamily: 'JetBrains Mono'
    }
});

async function renderMermaidBlocks() {
    const codeBlocks = document.querySelectorAll('code.language-mermaid, code.mermaid');

    for (const block of codeBlocks) {
        let content = block.textContent || '';
        const txt = document.createElement('textarea');
        txt.innerHTML = content;
        content = txt.value.trim();

        const pre = block.parentElement;
        const div = document.createElement('div');
        div.className = 'mermaid';
        div.textContent = content;
        div.style.textAlign = 'center';

        if (pre) {
            pre.replaceWith(div);
        }
    }

    try {
        await mermaid.run({ querySelector: '.mermaid' });
    } catch (err) {
        console.error('Mermaid Drawing Failed:', err);
    }
}

document.addEventListener('DOMContentLoaded', renderMermaidBlocks);
