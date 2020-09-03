use neon::prelude::*;
use openssl::x509::*;


fn pem_to_der(mut cx: FunctionContext) -> JsResult<JsBuffer>{
    let buffer: Handle<JsBuffer> = cx.argument(0)?;
    let cert = cx.borrow(&buffer, |data| {
        X509::from_pem(data.as_slice())
    });
    let der = cert.unwrap().to_der().unwrap();
    let ret = cx.buffer(der.len() as u32)?;

    for (i, v) in der.iter().enumerate() {
        let value = cx.number(*v);
        ret.set(&mut cx, i as u32, value ).unwrap();
    }
    
    Ok(ret)
}

fn der_to_pem(mut cx: FunctionContext) -> JsResult<JsBuffer>{
    let buffer: Handle<JsBuffer> = cx.argument(0)?;
    let cert = cx.borrow(&buffer, |data| {
        X509::from_der(data.as_slice())
    });
    let pem = cert.unwrap().to_pem().unwrap();
    let ret = cx.buffer(pem.len() as u32)?;
    
    for (i, v) in pem.iter().enumerate() {
        let value = cx.number(*v);
        ret.set(&mut cx, i as u32, value ).unwrap();
    }

    Ok(ret)
}

register_module!(mut cx, {
    cx.export_function("pemToDER", pem_to_der)?;
    cx.export_function("derToPEM", der_to_pem)?;
    Ok(())
});

