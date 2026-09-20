const fs=require('fs');
const posJS=fs.readFileSync(process.argv[2],'utf8');
const store={};
global.sessionStorage={getItem:k=>k in store?store[k]:null,
  setItem:(k,v)=>{store[k]=String(v);},removeItem:k=>{delete store[k];}};

// simula una carga de pagina; navType: 'navigate' | 'reload'
function cargar(path,navType,scrollY){
  const lis={}; let scrolledTo=null;
  global.location={pathname:path};
  global.performance={getEntriesByType:()=>[{type:navType}]};
  global.window={scrollY,addEventListener:(t,f)=>{lis[t]=f;},scrollTo:(x,y)=>{scrolledTo=y;}};
  global.document={readyState:'loading',addEventListener:(t,f,c)=>{lis['doc:'+t]=f;}};
  eval(posJS);
  return {
    cargaCompleta(){global.document.readyState='complete'; lis.load&&lis.load();},
    enviarFormulario(){lis['doc:submit']&&lis['doc:submit']();},
    irse(){lis.beforeunload&&lis.beforeunload();},
    donde(){return scrolledTo;}
  };
}

// 1) estas a media pagina y pulsas Quitar -> al volver debe restaurar la posicion
let p=cargar('/cuarentena','navigate',850);
p.enviarFormulario();                       // POST de "Quitar"
p=cargar('/cuarentena','navigate',0);       // la pagina vuelve, arriba del todo
p.cargaCompleta();
if(p.donde()!==850) throw new Error('no restauro tras la accion: '+p.donde());
console.log('OK  tras pulsar Quitar vuelve a la posicion donde estabas (y=850)');

// 2) recarga automatica cada 5 min: tambien debe conservar la posicion
p=cargar('/cuarentena','navigate',600); p.irse();
p=cargar('/cuarentena','reload',0); p.cargaCompleta();
if(p.donde()!==600) throw new Error('no restauro en la recarga: '+p.donde());
console.log('OK  la recarga automatica no te manda arriba (y=600)');

// 3) navegar a otra pestana y volver a mano NO debe saltar solo
p=cargar('/cuarentena','navigate',700); p.irse();
p=cargar('/cuarentena','navigate',0); p.cargaCompleta();
if(p.donde()!==null) throw new Error('salto sin motivo al entrar a la pagina: '+p.donde());
console.log('OK  al entrar normalmente a la pagina NO fuerza ningun salto');

// 4) estando arriba del todo, no hace nada raro
p=cargar('/cuarentena','navigate',0); p.enviarFormulario();
p=cargar('/cuarentena','navigate',0); p.cargaCompleta();
if(p.donde()!==null) throw new Error('scroll innecesario');
console.log('OK  si estabas arriba, no hay salto');
console.log('\nTODO OK');
