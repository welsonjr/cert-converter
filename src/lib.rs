use neon::prelude::*;
use neon::types::buffer::TypedArray;
use openssl::pkcs12::*;
use openssl::pkey::*;
use openssl::x509::*;

fn convert_to_jsbuffer<'a>(mut cx: FunctionContext<'a>, data: &Vec<u8>) -> JsResult<'a, JsBuffer> {
    let ret = cx.buffer(data.len())?;
    for (i, &v) in data.iter().enumerate() {
        let value = cx.number(v);
        ret.set(&mut cx, i as u32, value).unwrap();
    }

    Ok(ret)
}

fn pem_to_der(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let buffer: Handle<JsBuffer> = cx.argument(0)?;
    let cert = X509::from_pem(buffer.as_slice(&cx)).expect("Wrong encoding");
    let der = cert.to_der().expect("Failed to convert");

    convert_to_jsbuffer(cx, &der)
}

fn der_to_pem(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let buffer: Handle<JsBuffer> = cx.argument(0)?;
    let cert = X509::from_der(buffer.as_slice(&cx)).expect("Wrong encoding");
    let pem = cert.to_pem().expect("Failed to convert");
    convert_to_jsbuffer(cx, &pem)
}

fn pem_to_pfx(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let key_password = cx.argument::<JsString>(0)?.value(&mut cx);
    let export_password = cx.argument::<JsString>(1)?.value(&mut cx);
    let key_buffer: Handle<JsBuffer> = cx.argument(2)?;
    let cert_buffer: Handle<JsBuffer> = cx.argument(3)?;

    let key = PKey::private_key_from_pem_passphrase(key_buffer.as_slice(&cx), key_password.as_bytes())
            .expect("Wrong key encoding or password");

    let cert = X509::from_pem(cert_buffer.as_slice(&cx)).expect("Wrong cert encoding");
    

    let pfx = Pkcs12::builder()
        .build(
            export_password.as_str(),
            "cert",
            key.as_ref(),
            cert.as_ref(),
        )
        .unwrap()
        .to_der()
        .unwrap();

    convert_to_jsbuffer(cx, &pfx)
}

register_module!(mut cx, {
    cx.export_function("pemToDer", pem_to_der)?;
    cx.export_function("derToPem", der_to_pem)?;
    cx.export_function("pemToPfx", pem_to_pfx)?;
    Ok(())
});
