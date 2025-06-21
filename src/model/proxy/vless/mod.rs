mod opts;

use opts::{Headers, Reality, Ws, H2};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

use crate::model::proxy::tool::{encode, encode_array, param};

#[derive(Serialize, Deserialize)]
pub(super) struct Vless {
    name: String,
    uuid: String,
    server: String,
    port: u16,
    tls: Option<bool>,
    flow: Option<String>,
    servername: Option<String>,
    alpn: Option<Vec<String>>,
    network: Option<String>,
    #[serde(rename = "reality-opts")]
    reality_opts: Option<Reality>,
    #[serde(rename = "ws-opts")]
    ws_opts: Option<Ws>,
    #[serde(rename = "h2-opts")]
    h2_opts: Option<H2>,
    #[serde(rename = "v2ray-http-upgrade")]
    v2ray_http_upgrade: Option<bool>,
}
impl Vless {
    pub(super) fn into_string(self) -> String {
        let Vless {
            name,
            uuid,
            server,
            port,
            tls,
            flow,
            servername,
            alpn,
            network,
            reality_opts,
            ws_opts,
            h2_opts,
            v2ray_http_upgrade,
        } = self;
        let name = utf8_percent_encode(&name, NON_ALPHANUMERIC);
        let (reality_flag, pbk, sid) = match reality_opts {
            Some(Reality {
                public_key,
                short_id,
            }) => (true, public_key, short_id),
            None => (false, None, None),
        };
        let (path, host) = match ws_opts {
            Some(Ws { path, headers }) => (
                path.map(encode),
                headers.and_then(|Headers { host }| host.map(encode)),
            ),
            None => match h2_opts {
                Some(H2 { host, path }) => (path.map(encode), host.map(encode_array)),
                None => (None, None),
            },
        };
        format!(
            "vless://{uuid}@{server}:{port}{}#{name}",
            match [
                // security参数
                match (reality_flag, tls) {
                    (true, _) => Some("security=reality".into()),
                    (false, Some(true)) => Some("security=tls".into()),
                    _ => None,
                },
                flow.map(param("flow")),
                network
                    .map(|n| if n == "ws" && v2ray_http_upgrade.unwrap_or(false) {
                        "httpupgrade".into()
                    } else {
                        n
                    })
                    .map(param("type")),
                servername.map(param("sni")),
                alpn.map(encode_array).map(param("alpn")),
                pbk.map(param("pbk")),
                sid.map(param("sid")),
                path.map(param("path")),
                host.map(param("host")),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<String>>()
            {
                params if params.is_empty() => "".into(),
                params => format!("?{}", params.join("&")),
            }
        )
    }
}
