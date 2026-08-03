const value = new URLSearchParams(window.location.search).get('value');
const output = document.querySelector('#output');
output.innerHTML = value;
document.write(value);
window.location.href = value;
