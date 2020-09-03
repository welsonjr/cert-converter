use neon::prelude::*;
use openssl::x509::*;
use openssl::pkey::*;
use openssl::pkcs12::*;


fn pem_to_der(mut cx: FunctionContext) -> JsResult<JsBuffer>{
    let buffer: Handle<JsBuffer> = cx.argument(0)?;
    let cert = cx.borrow(&buffer, |data| {
        X509::from_pem(data.as_slice()).expect("Wrong encoding")
    });
    let der = cert.to_der().expect("Failed to convert");
    let ret = cx.buffer(der.len() as u32)?;

    for (i, &v) in der.iter().enumerate() {
        let value = cx.number(v);
        ret.set(&mut cx, i as u32, value ).unwrap();
    }
    
    Ok(ret)
}

fn der_to_pem(mut cx: FunctionContext) -> JsResult<JsBuffer>{
    let buffer: Handle<JsBuffer> = cx.argument(0)?;
    let cert = cx.borrow(&buffer, |data| {
        X509::from_der(data.as_slice()).expect("Wrong encoding")
    });
    let pem = cert.to_pem().expect("Failed to convert");
    let ret = cx.buffer(pem.len() as u32)?;
    
    for (i, &v) in pem.iter().enumerate() {
        let value = cx.number(v);
        ret.set(&mut cx, i as u32, value ).unwrap();
    }

    Ok(ret)
}

fn pem_to_pfx(mut cx: FunctionContext) -> JsResult<JsBuffer>{
    let key_password = cx.argument::<JsString>(0)?.value();
    let key_buffer: Handle<JsBuffer> = cx.argument(1)?;
    let cert_buffer: Handle<JsBuffer> = cx.argument(2)?;

    let key = cx.borrow(&key_buffer, |data| {
        PKey::private_key_from_pem_passphrase(data.as_slice(),key_password.as_bytes()).expect("Wrong key encoding or password")
    });

    let cert = cx.borrow(&cert_buffer, |data| {
        X509::from_pem(data.as_slice()).expect("Wrong cert encoding")
    });

    let pfx = Pkcs12::builder()
        .build("","cert",key.as_ref(),cert.as_ref())
        .unwrap()
        .to_der()
        .unwrap();

    let ret = cx.buffer(pfx.len() as u32)?;
    for (i, &v) in pfx.iter().enumerate() {
        let value = cx.number(v);
        ret.set(&mut cx, i as u32, value ).unwrap();
    }

    Ok(ret)
}

register_module!(mut cx, {
    cx.export_function("pemToDer", pem_to_der)?;
    cx.export_function("derToPem", der_to_pem)?;
    cx.export_function("pemToPfx", pem_to_pfx)?;
    Ok(())
});

