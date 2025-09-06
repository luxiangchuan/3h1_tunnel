import { connect } from 'cloudflare:sockets';
import { sha224Encrypt } from './encrypt.js';
import { base64Decode, base64Encode } from './base64.js';
import { fetchGitHubFile, fetchWebPageContent } from './crawler.js';
import { ipsPaging, hostPortParser, socks5AddressParser, generateIPsFromCIDR } from './address.js';
import { getBaseConfig, buildLinks, buildYamls, buildJsons } from './output.js';

let userID = '61098bdc-b734-4874-9e87-d18b1ef1cfaf';
let sha224Password = 'b379f280b9a4ce21e465cb31eea09a8fe3f4f8dd1850d9f630737538'; // sha224Encrypter('a8b047f5-9d2f-441b-bb4e-9866a645b945')
let landingAddress = '';
let socks5Address = ''; // 格式: user:pass@host:port、:@host:port
// NAT64 IPv6 前缀，设置的值已失效，暂时保留，期望未来能使用，新值从环境变量传入覆盖
let nat64IPv6Prefix = `${["2001", "67c", "2960", "6464"].join(":")}::`;

let parsedLandingAddress = { hostname: null, port: 443 };
let parsedSocks5Address = {};
let enableSocks = false;

// 控制 Skc0swodahs 协议的两个关键参数
let s5Lock = false; // true=启用，false=禁用
let allowedRules = ["0.0.0.0/0", "::/0"]; // 你连接节点时，所用的公网IP，是否在这个范围内？不在就不允许连接，支持CIDR和具体的IP地址

// 重定向的域名列表
const domainList = [
	'https://www.bilibili.com',
	'https://www.nicovideo.jp',
	'https://tv.naver.com',
	'https://www.hotstar.com',
	'https://www.netflix.com',
	'https://www.dailymotion.com',
	'https://www.youtube.com',
	'https://www.hulu.com',
	'https://fmovies.llc',
	'https://hdtodayz.to',
	'https://radar.cloudflare.com',
];

// 设置环境变量的默认值
const DEFAULTS = {
	github: {
		GITHUB_TOKEN: '', // 令牌
		GITHUB_OWNER: '', // 仓库所有者
		GITHUB_REPO: '', // 仓库名称
		GITHUB_BRANCH: 'main', // 分支名称
		GITHUB_FILE_PATH: 'README.md', // 文件路径(相对于仓库根目录)
	},
	password: {
		CONFIG_PASSWORD: '', // 查看节点配置的密码
		SUB_PASSWORD: '', // 查看节点订阅的密码
	},
	urls: {
		DATA_SOURCE_URL: 'https://raw.githubusercontent.com/juerson/3h1_tunnel/refs/heads/master/domain.txt', // 数据源URL
		CLASH_TEMPLATE_URL: 'https://raw.githubusercontent.com/juerson/3h1_tunnel/refs/heads/master/clashTemplate.yaml', // clash模板
	},
};

// 手动这里设置最大节点数（实际中，其中的key键依次是v2ray、singbox、clash）
const defaultMaxNodeMap = {
	'djJyYXk=': {
		upperLimit: 2000, // 最大上限
		default: 300, // 默认值，传入的数据不合法使用它
	},
	'c2luZ2JveA==': {
		upperLimit: 100,
		default: 30,
	},
	"Y2xhc2g=": {
		upperLimit: 100,
		default: 30,
	},
	'': {
		// 这个用于当target输入错误兜底的
		upperLimit: 500,
		default: 300,
	},
};

export default {
	async fetch(request, env, ctx) {
		try {
			userID = env.UUID4 || userID;
			let password = env.USERPWD || userID; // 应用trojan节点，没有设置，就使用前面的userID
			sha224Password = sha224Encrypt(password);

			// 下面s5Lock和allowedRules控制ss协议
			s5Lock = (() => {
				const v = env.ENABLED_S5;
				if (typeof v === 'boolean') return v;
				if (typeof v === 'string') return ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
				return s5Lock;
			})();
			const raw = (env.ALLOWED_RULES ?? "").trim().split(/[, \n\r\t]+/).map(x => x.trim()).filter(Boolean);
			allowedRules = raw.length > 0 ? raw : ["0.0.0.0/0", "::/0"];

			let landingAddr = env.LANDING_ADDRESS || landingAddress;
			let socks5Addr = env.SOCKS5 || socks5Address;
			nat64IPv6Prefix = env.NAT64 || nat64IPv6Prefix; // 不要将整个nat64 prefix cidr传入使用

			const url = new URL(request.url);
			const path = url.pathname;
			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const config = {
					env: extractGroupedEnv(env, DEFAULTS),
					query: extractUrlParams(url, defaultMaxNodeMap),
					subParameter: {
						// vless节点的userID => uuid
						uuid: userID,
						// trojan节点的密码
						password: password,
						// 是否支持ss协议，不支持就不要生成订阅
						onSs: s5Lock,
					},
				};
				return await handleRequest(path, config, defaultMaxNodeMap);
			} else {
				// 复位，防止上次请求的状态影响本次请求
				parsedSocks5Address = {};
				enableSocks = false;

				if (path.includes('/pyip=')) {
					landingAddr = path.split('/pyip=')[1];
					enableSocks = false;
				} else if (path.includes('/socks=')) {
					socks5Addr = path.split('/socks=')[1];
					enableSocks = true;
				}
				if (socks5Addr) {
					parsedSocks5Address = socks5AddressParser(socks5Addr);
				} else if (landingAddr) {
					let poxyaddr = '';
					if (landingAddr.includes(',')) {
						const arr = landingAddr.split(',');
						const randomIndex = Math.floor(Math.random() * arr.length);
						poxyaddr = arr[randomIndex].trim();
					} else {
						poxyaddr = landingAddr.trim();
					}
					parsedLandingAddress = hostPortParser(poxyaddr);
				}
				return await handleWebSocket(request);
			}
		} catch (err) {
			return new Response(err.toString());
		}
	},
};

async function handleRequest(path, config, defaultMaxNodeMap) {
	const { target, hostName, pwdPassword, defaultPort, maxNode, page, nodePath, cidr } = config.query;
	const { CONFIG_PASSWORD, SUB_PASSWORD } = config.env.password;

	const { DATA_SOURCE_URL, CLASH_TEMPLATE_URL } = config.env.urls;
	const github = config.env.github;

	// 检查GitHub配置是否完整，任何一项参数为空都视为不完整

	// 替换模板，匹配空白+符号+空白+占位符，这里指“  - ${proxies}”和“      - ${proxy_name}”所在行


	switch (path) {
		case '/':
			const randomDomain = domainList[Math.floor(Math.random() * domainList.length)];
			return Response.redirect(randomDomain, 301);
		case `/config`:
			let html_doc = '404 Not Found!',
				status = 404;
			if (pwdPassword == CONFIG_PASSWORD) {
				html_doc = getBaseConfig(config?.subParameter, hostName, nodePath);
				status = 200;
			}
			return new Response(html_doc, { status: status, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		case '/sub':
			if (pwdPassword == SUB_PASSWORD) {
				let ipsArray = generateIPsFromCIDR(cidr, maxNode);
				if (ipsArray.length === 0) {
					let ipContents = '';
					if (isGitHubConfigComplete(github)) {
						try {
							const file = await fetchGitHubFile(
								github?.GITHUB_TOKEN,
								github?.GITHUB_OWNER,
								github?.GITHUB_REPO,
								github?.GITHUB_FILE_PATH,
								github?.GITHUB_BRANCH
							);
							ipContents = new TextDecoder().decode(file.body);
						} catch (e) {
							console.log(`获取GitHub的数据失败：${e.message}`);
						}
					}
					if (!ipContents.trim()) ipContents = await fetchWebPageContent(DATA_SOURCE_URL);
					if (!ipContents.trim()) {
						return new Response('Null Data', { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
					}
					ipsArray = ipContents
						.trim()
						.split(/\r\n|\n|\r/)
						.map((line) => line.trim())
						.filter((line) => line.length > 0);
				}

				let upperLimit = defaultMaxNodeMap[target]?.upperLimit ?? defaultMaxNodeMap['']?.upperLimit;
				let defaultCount = defaultMaxNodeMap[target]?.default ?? defaultMaxNodeMap['']?.default;
				let ipsResult = ipsPaging(ipsArray, maxNode, page, upperLimit, defaultCount);
				if (ipsResult?.hasError) {
					return new Response((ipsResult.message, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }));
				}

				let htmlDoc = 'Not Found!';
				if (target === 'djJyYXk=') {
					// v2ray
					htmlDoc = buildLinks(ipsResult?.chunkedIPs, config?.subParameter, hostName, nodePath, defaultPort);
				} else if (target === 'c2luZ2JveA==') {
					// singbox
					let [_, outbds] = buildJsons(ipsResult?.chunkedIPs, config?.subParameter, hostName, nodePath, defaultPort);
					if (outbds.length > 0) htmlDoc = base64Decode('ew0KICAib3V0Ym91bmRzIjogWw0KI291dGJkcyMNCiAgXQ0KfQ').replace('#outbds#', outbds.join(',\n'));
				} else if (target === 'Y2xhc2g=') {
					// clash
					const isCFworkersDomain = hostName.endsWith(base64Decode('d29ya2Vycy5kZXY'));
					if (isCFworkersDomain) {
						htmlDoc = base64Decode(
							'6K2m5ZGK77ya5L2/55So5Z+f5ZCNI2hvc3ROYW1lI+eUn+aIkOeahGNsYXNo6K6i6ZiF5peg5rOV5L2/55So77yB57uI5q2i5pON5L2c44CC'
						).replace('#hostName#', hostName);
						return new Response(htmlDoc, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
					}
					let [nStr, poies] = buildYamls(ipsResult?.chunkedIPs, config?.subParameter, hostName, nodePath, defaultPort);
					let confTemplate = await fetchWebPageContent(CLASH_TEMPLATE_URL);
					if (poies.length > 0 && poies.length > 0) {
						htmlDoc = replaceTemplate(confTemplate, {
							proxies: poies.join('\n'),
							proxy_name: nStr.map((ipWithPort) => `      - ${ipWithPort}`).join('\n'),
						});
					}
				}
				return new Response(htmlDoc, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
			}
		default:
			return new Response('Not Found!', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
	}
}


// ————————————————————————— 获取 env 变量 和 url 参数 ————————————————————————

function extractGroupedEnv(env, groupedDefaults, encodeFields = ['CONFIG_PASSWORD', 'SUB_PASSWORD']) {
	const result = {};

	for (const [groupName, vars] of Object.entries(groupedDefaults)) {
		result[groupName] = {};
		for (const [key, defaultVal] of Object.entries(vars)) {
			let value = env[key] ?? defaultVal;
			// 如果字段在encodeFields中，则对其值进行URI编码
			if (encodeFields.includes(key)) {
				value = encodeURIComponent(String(value));
			}
			result[groupName][key] = value;
		}
	}

	return result;
}

function extractUrlParams(url, defaultMaxNodeMap, encodeFields = ['pwdPassword']) {
	const search = url.searchParams;
	const target = base64Encode(search.get('target')) || '';
	const defaultMax = defaultMaxNodeMap[target]?.default ?? defaultMaxNodeMap['']?.default; // ??后面的代码，用于预防target输入错误的情况
	const rawParams = {
		target,
		hostName: search.get('host') || url.hostname,
		pwdPassword: search.get('pwd') || '',
		defaultPort: parseInt(search.get('port') || '0', 10),
		maxNode: parseInt(search.get('max') || defaultMax.toString(), 10),
		page: parseInt(search.get('page') || '1', 10),
		nodePath: search.get('path') || "/", // 节点中的path值，可以改为/?ed=2048、/?ed=2560、/pyip=x.x.x.x、/socks=xx:xx@x.x.x.x:port
		cidr: search.get('cidr') || '',
	};

	for (const key of encodeFields) {
		if (key in rawParams) {
			rawParams[key] = encodeURIComponent(rawParams[key]);
		}
	}

	return rawParams;
}
