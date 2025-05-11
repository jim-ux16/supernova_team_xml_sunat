# xml-sunat

![Logo de la superintendencia nacional de administración tributaria - SUNAT](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRUkvtg9L1oBVOoWUMqrwmLVo4Fc4QF5xoNsg&s)

xml-sunat es una librería de JavaScript para poder firmar xml para la entidad de SUNAT. La librería depende de [xml-crypto](https://www.npmjs.com/package/xml-crypto).


## Instalación

```bash
# npm
npm i @supernova-team/xml-sunat
# pnpm
pnpm add @supernova-team/xml-sunat
```

## Modo de uso

Para poder firmar un xml, debemos importar la clase **XmlSignature** y pasar los argumentos al constructor.

```javascript
import { XmlSignature } from "@supernova-team/xml-sunat";
import path from 'node:path';
import fs from 'fs';

//Ruta a tu archivo pfx
const pfxFilePath = path.join("path", "to", "cdr"); 
//Contraseña de tu archivo .pfx
const password = "pfxPassword";
//Xml a firmar
const xmlStringStructure = "<Invoice>...</Invoice>";

const sig = new XmlSignature(pfxFilePath, password, xmlStringStructure);

sig.getSignedXML().then((signedXML)=> {
    fs.writeFileSync('your-filename.xml', signedXML);
})
.catch((err) => {
    console.error('An error has occurred: '+ err);
})
;
```

## Licencia

[MIT](https://choosealicense.com/licenses/mit/)