import { XmlSignature } from ".";

describe("XmlSignature", () => {

    let xmlSignature:XmlSignature;

    test("should throw an error because .pfx doesn't exists.", () => {

        expect(xmlSignature = new XmlSignature(".pfx", "password", "")).toThrow();

    });





});