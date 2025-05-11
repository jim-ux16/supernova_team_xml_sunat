import {DOMParser} from "@xmldom/xmldom";
import fs from 'fs/promises';
import { existsSync } from "fs";
import forge from 'node-forge';
import { Key } from "./interfaces/key";
import  { SignedXml } from 'xml-crypto';

export class XmlSignature{

    private pfxFilePath!:string; 
    private password!:string;
    private xmlStringStructure!:string;

    //Signature configuration
    private readonly canonicalizationAlgorithm:string = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    private readonly signatureAlgorithm:string = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    private readonly signXpath:string = "//*[local-name()='Invoice']";
    private readonly transforms:string[] = ['http://www.w3.org/2000/09/xmldsig#enveloped-signature','http://www.w3.org/TR/2001/REC-xml-c14n-20010315'];
    private readonly digestAlgorithm:string = 'http://www.w3.org/2001/04/xmlenc#sha256';

    /**
     * 
     * @param {string} pfxFilePath - The .pfx file path
     * @param {string} password - The password of the .pfx file
     * @param {string} xmlStringStructure - The XML string structure to be signed
     */
    constructor(pfxFilePath:string , password:string, xmlStringStructure:string ){

        this.pfxFilePath = pfxFilePath;
        this.password = password;
        this.xmlStringStructure = xmlStringStructure;

    }

    private verifyXMLStructure(){

        const domXML = new DOMParser().parseFromString(this.xmlStringStructure, "text/xml");
        const signatureNode = domXML.getElementsByTagName("ext:ExtensionContent");

        if(signatureNode.length === 0){
            throw new Error('Error, the xml structure does not contain the signature node called "ext:ExtensionContent"');
        }

    }

    /**
     * @throws {Error} Error if the XML structure is not valid
     * @throws {Error} Error if the PFX file is not valid
     * @throws {Error} Error if the PFX file does not contain a private key
     * @returns {Promise<string>} The signed XML string
     */
    async getSignedXML():Promise<string>{

        this.verifyXMLStructure();
        const key:Key = await this.convertPFXtoPEM();

        //Signature configuration
        const sig = new SignedXml({
            privateKey: key.privateKey,
            signatureAlgorithm: this.signatureAlgorithm,
            canonicalizationAlgorithm: this.canonicalizationAlgorithm,
            publicCert: key.cert,
            getKeyInfoContent: () => {
                return `<ds:X509Data><ds:X509Certificate>${key.cert.replace(/-----BEGIN CERTIFICATE-----/g, '').replace(/-----END CERTIFICATE-----/g, '').replace(/(\r\n|\n|\r)/gm, "").trim()}</ds:X509Certificate></ds:X509Data>`;
            }  
        });

        //Signature reference
        sig.addReference({
            xpath: this.signXpath,
            transforms: this.transforms,
            digestAlgorithm: this.digestAlgorithm,
            isEmptyUri: true
        });

        //Sign the XML
        sig.computeSignature(this.xmlStringStructure, {
            attrs: {
                Id: 'SignatureSP',
            },
            location: { reference: "//*[local-name(.)='ExtensionContent']", action: "prepend" },
            prefix: "ds",
        })

        return sig.getSignedXml();

    }

    private async convertPFXtoPEM():Promise<Key>{

        //Check empty file
        if(!this.pfxFilePath || !this.pfxFilePath.endsWith('.pfx')){
            throw new Error('Error with the pfx file path, it should be a .pfx file');
        }

        //Check if exists file
        await new Promise<void>((resolve, reject) => {
            if(existsSync(this.pfxFilePath)){
                resolve();
            }else{
                reject(new Error(`Error, the file ${this.pfxFilePath} does not exist`));
            }
        });

        const pfxBuffer = await fs.readFile(this.pfxFilePath);

        const pfxAsn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
        const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, this.password);
        const privateKeyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag })[forge.pki.oids.pkcs8ShroudedKeyBag];

        // Check if private key bags are empty
        if (!privateKeyBags || privateKeyBags.length === 0) {
            throw new Error('Error, no private key bag found in the PFX file');
        }
        const privateKeyBag = privateKeyBags[0];

        // Check if private key is empty
        const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag })[forge.pki.oids.certBag];
        if (!certBags || certBags.length === 0) {
            throw new Error('Error, no certificate bag found in the PFX file');
        }
        const certBag = certBags[0];

        const privateKeyPem = forge.pki.privateKeyToPem(privateKeyBag!.key!);
        const certPem = forge.pki.certificateToPem(certBag!.cert!);

        return {
            privateKey: privateKeyPem,
            cert: certPem
        };



    }

}