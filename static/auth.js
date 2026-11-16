(function(){const t=localStorage.getItem('pl_token');const g=document.getElementById('gate'),a=document.getElementById('app');
if(t&&g&&a){g.classList.add('hidden');a.classList.remove('hidden')}
const nl=document.getElementById('nav-login'),nr=document.getElementById('nav-register');
if(t&&nl&&nr){nl.classList.add('hidden');nr.classList.add('hidden')}})();
window.plAuth=()=>({token:localStorage.getItem('pl_token')||'',headers:()=>({'Authorization':'Bearer '+(localStorage.getItem('pl_token')||''),'Content-Type':'application/json'})});
