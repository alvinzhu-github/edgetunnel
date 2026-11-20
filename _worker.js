const Version = '2026-10-08 22:23:27';
let config_JSON, 缓存SOCKS5白名单 = null, 调试日志打印 = false;
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io', EDT_版本号 = Number(String(Version).replace(/\D+/g, ''));
///////////////////////////////////////////////////////全局常量和工具函数///////////////////////////////////////////////
const WS早期数据最大字节 = 8 * 1024, WS早期数据最大头长度 = Math.ceil(WS早期数据最大字节 * 4 / 3) + 4;
const 上行合包目标字节 = 20 * 1024, 上行队列最大字节 = 16 * 1024 * 1024, 上行队列最大条目 = 4096;
const 下行Grain包字节 = 32 * 1024, 下行Grain尾部阈值 = 512, 下行Grain低水位字节 = Math.max(4096, 下行Grain尾部阈值 * 12), 下行Grain最大等待轮次 = 4;
let TCP并发拨号数 = 2, 反代并发拨号数 = 1, 预加载竞速拨号 = false;
///////////////////////////////////////////////////////查杀特征码///////////////////////////////////////////////
const 特征码字典 = [
	(Proxy.name + "IP").toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];
const 汇聚订阅_UA = 'v2rayN/edge' + 'tunnel (https://github.com/' + 特征码字典[1] + '/edge' + 'tunnel)';
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
	async fetch(request, env, ctx) {
		let 请求URL文本 = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const 请求URL锚点索引 = 请求URL文本.indexOf('#');
		const 请求URL主体部分 = 请求URL锚点索引 === -1 ? 请求URL文本 : 请求URL文本.slice(0, 请求URL锚点索引);
		if (!请求URL主体部分.includes('?') && /%3f/i.test(请求URL主体部分)) {
			const 请求URL锚点部分 = 请求URL锚点索引 === -1 ? '' : 请求URL文本.slice(请求URL锚点索引);
			请求URL文本 = 请求URL主体部分.replace(/%3f/i, '?') + 请求URL锚点部分;
		}
		const url = new URL(请求URL文本);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
		const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const 访问路径 = url.pathname.slice(1).toLowerCase();
		调试日志打印 = ['1', 'true'].includes(env.DEBUG) || 调试日志打印;
		预加载竞速拨号 = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || 预加载竞速拨号;
		反代并发拨号数 = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || 反代并发拨号数);
		TCP并发拨号数 = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || TCP并发拨号数);
		if (!env.TCP_CONCURRENT_DIAL && TCP并发拨号数 !== 1 && 识别运营商(request) === 'cmcc') TCP并发拨号数 = 1;
		let 默认反代IP = (`${request.cf.colo}.${特征码字典[0]}.${特征码字典[1]}SsSs.nEt`).toLowerCase(), 默认反代兜底 = true;
		if (env.PROXYIP) {
			const proxyIPs = await 整理成数组(env.PROXYIP);
			默认反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			默认反代兜底 = false;
		};
		const 访问IP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || '未知IP';
		const [本机标识头, 本机标识键] = 获取本机标识(userID);
		if (缓存SOCKS5白名单 === null) {
			if (env.GO2SOCKS5) SOCKS5白名单 = [...new Set(SOCKS5白名单.concat(await 整理成数组(env.GO2SOCKS5)))];
			缓存SOCKS5白名单 = SOCKS5白名单;
		} else SOCKS5白名单 = 缓存SOCKS5白名单;
		if (访问路径 === 'version') {// 版本信息接口
			const 请求UUID = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(请求UUID)) {
				const 目标UUID = String(userID).toLowerCase();
				let 请求前8总和 = 0, 目标前8总和 = 0;
				for (let i = 0; i < 8; i++) {
					const 请求码 = 请求UUID.charCodeAt(i);
					请求前8总和 += 请求码 <= 57 ? 请求码 - 48 : 请求码 - 87;
					const 目标码 = 目标UUID.charCodeAt(i);
					目标前8总和 += 目标码 <= 57 ? 目标码 - 48 : 目标码 - 87;
				}
				if (请求前8总和 === 目标前8总和 && 请求UUID.slice(-12) === 目标UUID.slice(-12)) return new Response(JSON.stringify({ Version: EDT_版本号 }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (管理员密码 && upgradeHeader === 'websocket') {// WebSocket代理
			const 反代上下文 = await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底);
			log(`[WebSocket] 命中请求: ${url.pathname}${url.search}`);
			return await 处理WS请求(request, userID, url, 反代上下文);
		} else if (管理员密码 && !访问路径.startsWith('admin/') && 访问路径 !== 'login' && request.method === 'POST') {// gRPC/叉HTTP代理
			const 反代上下文 = await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底);
			const 命中叉HTTP特征 = !!request.headers.get(本机标识头) || !!url.searchParams.get(本机标识键);
			if (!命中叉HTTP特征 && contentType.startsWith('application/grpc')) {
				log(`[gRPC] 命中请求: ${url.pathname}${url.search}`);
				return await 处理gRPC请求(request, userID, 反代上下文);
			}
			log(`[叉HTTP] 命中请求: ${url.pathname}${url.search}`);
			return await 处理叉HTTP请求(request, userID, 反代上下文);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
			if (env.KV && typeof env.KV.get === 'function') {
				const 区分大小写访问路径 = url.pathname.slice(1);
				if (区分大小写访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (访问路径 === 'login') {//处理登录页面和登录请求
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const 输入密码 = params.get('password');
						if (输入密码 === (typeof 管理员密码 === 'string' ? 管理员密码.replace(/[\r\n]/g, '') : 管理员密码)) {
							// 密码正确，设置cookie并返回成功标记
							const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
							return 响应;
						}
					}
					return fetch(Pages静态页面 + '/login');
				} else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {//验证cookie后响应管理页面
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					// 没有cookie或cookie错误，跳转到/login页面
					if (!authCookie || authCookie !== await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
					if (访问路径 === 'admin/log.json') {// 读取日志内容
						const 读取日志内容 = await env.KV.get('log.json') || '[]';
						return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {// 查询请求量
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (区分大小写访问路径 === 'admin/getADDAPI') {// 验证优选API
						if (url.searchParams.get('url')) {
							const 待验证优选URL = url.searchParams.get('url');
							try {
								new URL(待验证优选URL);
								const 请求优选API内容 = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443', 本机标识头);
								let 优选API的IP = 请求优选API内容[0].length > 0 ? 请求优选API内容[0] : 请求优选API内容[1];
								优选API的IP = 优选API的IP.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (访问路径 === 'admin/check') {// 代理检查
						const 代理协议 = ['socks5', 'http', 'https', 'turn', 'sstp'].find(类型 => url.searchParams.has(类型)) || null;
						if (!代理协议) return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						const 代理参数 = url.searchParams.get(代理协议);
						const startTime = Date.now();
						let 检测代理响应;
						try {
							const checkParsed = await 获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议));
							const { username, password, hostname, port } = checkParsed;
							const 完整代理参数 = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
							try {
								const 检测主机 = 'cloudflare.com', 检测端口 = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
								const TCP连接 = 创建请求TCP连接器(request);
								let tcpSocket = null, tlsSocket = null;
								try {
									tcpSocket = 代理协议 === 'socks5'
										? await socks5Connect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
										: 代理协议 === 'turn'
											? await turnConnect(checkParsed, 检测主机, 检测端口, TCP连接)
											: 代理协议 === 'sstp'
												? await sstpConnect(checkParsed, 检测主机, 检测端口, TCP连接)
												: (代理协议 === 'https' && isIPHostname(hostname)
													? await httpsConnect(检测主机, 检测端口, new Uint8Array(0), TCP连接, checkParsed)
													: await httpConnect(检测主机, 检测端口, new Uint8Array(0), 代理协议 === 'https', TCP连接, checkParsed));
									if (!tcpSocket) throw new Error('无法连接到代理服务器');
									tlsSocket = new TlsClient(tcpSocket, { serverName: 检测主机, insecure: true });
									await tlsSocket.handshake();
									await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${检测主机}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
									let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
									const 最大响应字节 = 64 * 1024;
									while (responseBuffer.length < 最大响应字节) {
										const value = await tlsSocket.read();
										if (!value) break;
										if (value.byteLength === 0) continue;
										responseBuffer = 拼接字节数据(responseBuffer, value);
										if (headerEndIndex === -1) {
											const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
											if (crlfcrlf !== -1) {
												headerEndIndex = crlfcrlf + 4;
												const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
												const statusLine = headers.split('\r\n')[0] || '';
												const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
												const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
												if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`代理检测请求失败: ${statusLine || '无效响应'}`);
												const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
												if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
												chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
											}
										}
										if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
										if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
									}
									if (headerEndIndex === -1) throw new Error('代理检测响应头过长或无效');
									const response = decoder.decode(responseBuffer);
									const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
									const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
									if (!ip || !loc) throw new Error('代理检测响应无效');
									检测代理响应 = { success: true, proxy: 代理协议 + "://" + 完整代理参数, ip, loc, responseTime: Date.now() - startTime };
								} finally {
									try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
								}
							} catch (error) {
								检测代理响应 = { success: false, error: error.message, proxy: 代理协议 + "://" + 完整代理参数, responseTime: Date.now() - startTime };
							}
						} catch (err) {
							检测代理响应 = { success: false, error: err.message, proxy: 代理协议 + "://" + 代理参数, responseTime: Date.now() - startTime };
						}
						return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await 读取config_JSON(env, host, userID, UA);

					if (访问路径 === 'admin/init') {// 重置配置为默认值
						try {
							config_JSON = await 读取config_JSON(env, host, userID, UA, true);
							ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
							config_JSON.init = '配置已重置为默认值';
							return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
						if (访问路径 === 'admin/config.json') { // 保存config.json配置
							try {
								const newConfig = await request.json();
								// 验证配置完整性
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// 保存到 KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (访问路径 === 'admin/cf.json') { // 保存cf.json配置
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// 保存到 KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (访问路径 === 'admin/tg.json') { // 保存tg.json配置
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存配置失败:', error);
								return new Response(JSON.stringify({ error: '保存配置失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (区分大小写访问路径 === 'admin/ADD.txt') { // 保存自定义优选IP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// 保存到 KV
								ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: '自定义IP已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('保存自定义IP失败:', error);
								return new Response(JSON.stringify({ error: '保存自定义IP失败: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: '不支持的POST请求路径' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (访问路径 === 'admin/config.json') {// 处理 admin/config.json 请求，返回JSON
						return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} else if (区分大小写访问路径 === 'admin/ADD.txt') {// 处理 admin/ADD.txt 请求，返回本地优选IP
						let 本地优选IP = await env.KV.get('ADD.txt') || 'null';
						if (本地优选IP == 'null') 本地优选IP = (await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口))[1];
						return new Response(本地优选IP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
					} else if (访问路径 === 'admin/cf.json') {// CF配置文件
						return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Admin_Login', config_JSON));
					return fetch(Pages静态页面 + '/admin' + url.search);
				} else if (访问路径 === 'logout' || uuidRegex.test(访问路径)) {//清除cookie并跳转到登录页面
					const 响应 = new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
					响应.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return 响应;
				} else if (访问路径 === 'sub') {//处理订阅请求
					const 订阅TOKEN = await MD5MD5(host + userID), 作为优选订阅生成器 = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/' + 特征码字典[1] + '/edge');
					const 请求TOKEN = url.searchParams.get('token');
					const 用户客户端请求订阅 = 请求TOKEN === 订阅TOKEN;
					const 当前日序号 = Math.floor(Date.now() / 86400000);
					const 订阅转换后端TOKEN种子 = base64SecretEncode(订阅TOKEN, userID);
					const [今日订阅转换后端专属TOKEN, 昨日订阅转换后端专属TOKEN] = await Promise.all([
						MD5MD5(订阅转换后端TOKEN种子 + 当前日序号),
						MD5MD5(订阅转换后端TOKEN种子 + (当前日序号 - 1)),
					]);
					const 订阅转换后端请求订阅 = 请求TOKEN === 今日订阅转换后端专属TOKEN || 请求TOKEN === 昨日订阅转换后端专属TOKEN;
					if (用户客户端请求订阅 || 订阅转换后端请求订阅 || 作为优选订阅生成器) {
						config_JSON = await 读取config_JSON(env, host, userID, UA);
						if (作为优选订阅生成器) ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.优选订阅生成.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Cache-Control": "no-store",
						};
						if (config_JSON.CF.Usage.success) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Number.isFinite(config_JSON.CF.Usage.max) ? (config_JSON.CF.Usage.max / 1000) * 1024 : 1024 * 100;
							responseHeaders["Subscription-Userinfo"] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=4102329600`; // 2099-12-31 到期时间
						}
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || 作为优选订阅生成器;
						const 订阅类型 = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
						const 协议类型 = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.协议类型 !== 'ss') ? 'tro' + 'jan' : config_JSON.协议类型;
						let 订阅内容 = '';
						if (订阅类型 === 'mixed') {
							const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let 完整优选IP = [], 其他节点LINK = '', 反代IP池 = [];

							if (!url.searchParams.has('sub') && config_JSON.优选订阅生成.local) { // 本地生成订阅
								const 完整优选列表 = config_JSON.优选订阅生成.本地IP库.随机IP ? (
									await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口)
								)[0] : await env.KV.get('ADD.txt') ? await 整理成数组(await env.KV.get('ADD.txt')) : (
									await 生成随机IP(request, config_JSON.优选订阅生成.本地IP库.随机数量, config_JSON.优选订阅生成.本地IP库.指定端口)
								)[0];
								const 优选API = [], 优选IP = [], 其他节点 = [];
								for (const 元素 of 完整优选列表) {
									if (元素.toLowerCase().startsWith('sub://')) {
										优选API.push(元素);
									} else {
										const 备注位置 = 元素.indexOf('#');
										const 地址部分 = 备注位置 > -1 ? 元素.slice(0, 备注位置) : 元素;
										const 备注部分 = 备注位置 > -1 ? 元素.slice(备注位置) : '';
										const subMatch = 元素.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const 优选IP作为反代IP = 元素.toLowerCase().includes('proxyip=true');
											if (优选IP作为反代IP) 优选API.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
											else 优选API.push('sub://' + subMatch[1].trim() + (元素.includes('#') ? ('#' + 元素.split('#')[1]) : ''));
										} else if (地址部分.toLowerCase().startsWith('https://')) {
											优选API.push(元素);
										} else if (地址部分.toLowerCase().includes('://')) {
											if (元素.includes('#')) {
												const 地址备注分离 = 元素.split('#');
												其他节点.push(地址备注分离[0] + '#' + encodeURIComponent(decodeURIComponent(地址备注分离[1])));
											} else 其他节点.push(元素);
										} else {
											if (地址部分.includes('*')) {
												优选IP.push(替换星号为随机字符(地址部分) + 备注部分);
											} else 优选IP.push(元素);
										}
									}
								}
								const 请求优选API内容 = await 请求优选API(优选API, '443', 本机标识头);
								const 合并其他节点数组 = [...new Set(其他节点.concat(请求优选API内容[1]))];
								其他节点LINK = 合并其他节点数组.length > 0 ? 合并其他节点数组.join('\n') + '\n' : '';
								const 优选API的IP = 请求优选API内容[0];
								反代IP池 = 请求优选API内容[3] || [];
								完整优选IP = [...new Set(优选IP.concat(优选API的IP))];
							} else { // 优选订阅生成器
								let 优选订阅生成器HOST = url.searchParams.get('sub') || config_JSON.优选订阅生成.SUB;
								const [优选生成器IP数组, 优选生成器其他节点] = await 获取优选订阅生成器数据(优选订阅生成器HOST, 本机标识头);
								完整优选IP = 完整优选IP.concat(优选生成器IP数组);
								其他节点LINK += 优选生成器其他节点;
							}
							const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
							订阅内容 = 其他节点LINK + 完整优选IP.map(原始地址 => {
								// 统一正则: 匹配 域名/IPv4/IPv6地址 + 可选端口 + 可选备注
								// 示例:
								//   - 域名: hj.xmm1993.top:2096#备注 或 example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles 或 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC 或 [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = 原始地址.match(regex);

								let 节点地址, 节点端口 = "443", 节点备注;

								if (match) {
									节点地址 = match[1];  // IP地址或域名(可能带方括号)
									节点端口 = match[2] ? match[2] : '443';  // 端口默认443，SS noTLS在生成链接时再映射
									节点备注 = match[3] || 节点地址;  // 备注,默认为地址本身
								} else {
									// 不规范的格式，跳过处理返回null
									console.warn(`[订阅内容] 不规范的IP格式已忽略: ${原始地址}`);
									return null;
								}

								let 完整节点路径 = config_JSON.完整节点路径;

								const 链式代理匹配 = 节点备注.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (链式代理匹配) {
									try {
										const 代理协议 = 链式代理匹配[1].toLowerCase(), 代理参数 = 链式代理匹配[2];
										const 链式代理数据 = { type: 代理协议, ...获取SOCKS5账号(代理参数, 获取代理默认端口(代理协议)) };
										完整节点路径 = `/video/${base64SecretEncode(JSON.stringify(链式代理数据), userID) + (config_JSON.启用0RTT ? '?ed=2560' : '')}`;
										节点备注 = 节点备注.replace(链式代理匹配[0], '').trim() || 节点地址;
									} catch (error) {
										console.warn(`[订阅内容] 链式代理解析失败，已忽略该指令: ${链式代理匹配[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (反代IP池.length > 0) {
									const 匹配到的反代IP = 反代IP池.find(p => p.includes(节点地址));
									if (匹配到的反代IP) 完整节点路径 = (`${config_JSON.PATH}/proxyip=${匹配到的反代IP}`).replace(/\/\//g, '/') + (config_JSON.启用0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) 完整节点路径 = 完整节点路径.replace(/,/g, '%2C');

								if (协议类型 === 'ss' && !作为优选订阅生成器) {
									if (!config_JSON.SS.TLS) {
										const TLS端口 = [443, 2053, 2083, 2087, 2096, 8443];
										const NOTLS端口 = [80, 2052, 2082, 2086, 2095, 8080];
										节点端口 = String(NOTLS端口[TLS端口.indexOf(Number(节点端口))] ?? 节点端口);
									}
									完整节点路径 = (完整节点路径.includes('?') ? 完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (完整节点路径 + '?enc=' + config_JSON.SS.加密方式)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) 完整节点路径 = 完整节点路径 + ';mux=0';
									return `${协议类型}://${btoa(config_JSON.SS.加密方式 + ':00000000-0000-4000-8000-000000000000')}@${节点地址}:${节点端口}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.随机路径 ? 随机路径(完整节点路径) : 完整节点路径) + (config_JSON.SS.TLS ? ';tls' : '')) + ECHLINK参数 + TLS分片参数}#${encodeURIComponent(节点备注)}`;
								} else {
									const 传输路径参数值 = 获取传输路径参数值(config_JSON, 完整节点路径, 作为优选订阅生成器);
									return `${协议类型}://00000000-0000-4000-8000-000000000000@${节点地址}:${节点端口}?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none&alpn=${encodeURIComponent(config_JSON.ALPN)}#${encodeURIComponent(节点备注)}`;
								}
							}).filter(item => item !== null).join('\n');
						} else { // 订阅转换
							const 订阅转换URL = `${config_JSON.订阅转换配置.SUBAPI}/sub?target=${订阅类型}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + 今日订阅转换后端专属TOKEN + '&cnIspCode=' + 识别运营商(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.订阅转换配置.SUBCONFIG)}&emoji=${config_JSON.订阅转换配置.SUBEMOJI}&list=${config_JSON.订阅转换配置.SUBLIST}&scv=${config_JSON.跳过证书验证}&xudp=${config_JSON.订阅转换配置.XUDP}&udp=${config_JSON.订阅转换配置.UDP}&tls13=${config_JSON.订阅转换配置.TLS13}&append_type=${config_JSON.订阅转换配置.APPEND_TYPE}&sort=${config_JSON.订阅转换配置.SORT}&expand=${config_JSON.订阅转换配置.EXPAND}`;
							try {
								const response = await fetch(订阅转换URL, { headers: { 'User-Agent': 'Subconverter for ' + 订阅类型 + ' edge' + 'tunnel (https://github.com/' + 特征码字典[1] + '/edge' + 'tunnel) Uid/0x' + 本机标识头 + ' Version/' + EDT_版本号 } });
								if (response.ok) {
									订阅内容 = await response.text();
									if (url.searchParams.has('surge') || ua.includes('surge')) 订阅内容 = Surge订阅配置文件热补丁(订阅内容, url.protocol + '//' + url.host + '/sub?token=' + 订阅TOKEN + '&surge', config_JSON);
								} else return new Response('订阅转换后端异常：' + response.statusText, { status: response.status });
							} catch (error) {
								return new Response('订阅转换后端异常：' + error.message, { status: 403 });
							}
						}

						if (!ua.includes('subconverter') && 用户客户端请求订阅) {
							const 打乱后HOSTS = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
							let 替换域名计数 = 0, 当前随机HOST = null;
							订阅内容 = 订阅内容
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
								.replace(/example\.com/g, () => {
									if (替换域名计数 % 2 === 0) {
										const 原始host = 打乱后HOSTS[Math.floor(替换域名计数 / 2) % 打乱后HOSTS.length];
										当前随机HOST = 替换星号为随机字符(原始host);
									}
									替换域名计数++;
									return 当前随机HOST;
								});
						}

						if (订阅类型 === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) 订阅内容 = btoa(订阅内容);

						if (订阅类型 === 'singbox') {
							订阅内容 = await Singbox订阅配置文件热补丁(订阅内容, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (订阅类型 === 'clash') {
							订阅内容 = Clash订阅配置文件热补丁(订阅内容, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(订阅内容, { status: 200, headers: responseHeaders });
					}
				} else if (访问路径 === 'locations') {//反代locations列表
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie && authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (访问路径 === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }) });
		}

		let 伪装页URL = env.URL || 'nginx';
		if (伪装页URL && 伪装页URL !== 'nginx' && 伪装页URL !== '1101') {
			伪装页URL = 伪装页URL.trim().replace(/\/$/, '');
			if (!伪装页URL.match(/^https?:\/\//i)) 伪装页URL = 'https://' + 伪装页URL;
			if (伪装页URL.toLowerCase().startsWith('http://')) 伪装页URL = 'https://' + 伪装页URL.substring(7);
			try { const u = new URL(伪装页URL); 伪装页URL = u.protocol + '//' + u.host } catch (e) { 伪装页URL = 'nginx' }
		}
		if (伪装页URL === '1101') return new Response(await html1101(url.host, 访问IP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const 反代URL = new URL(伪装页URL), 新请求头 = new Headers(request.headers);
			新请求头.set('Host', 反代URL.host);
			新请求头.set('Referer', 反代URL.origin);
			新请求头.set('Origin', 反代URL.origin);
			if (!新请求头.has('User-Agent') && UA && UA !== 'null') 新请求头.set('User-Agent', UA);
			const 反代响应 = await fetch(反代URL.origin + url.pathname + url.search, { method: request.method, headers: 新请求头, body: request.body, cf: request.cf });
			const 内容类型 = 反代响应.headers.get('content-type') || '';
			// 只处理文本类型的响应
			if (/text|javascript|json|xml/.test(内容类型)) {
				const 响应内容 = (await 反代响应.text()).replaceAll(反代URL.host, url.host);
				return new Response(响应内容, { status: 反代响应.status, headers: { ...Object.fromEntries(反代响应.headers), 'Cache-Control': 'no-store' } });
			}
			return 反代响应;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
///////////////////////////////////////////////////////////////////////叉HTTP传输数据///////////////////////////////////////////////
const HPACKHuffman码长 = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30
];

function 获取本机标识(yourUUID) {
	return [yourUUID.slice(1, 7), '_' + yourUUID.slice(25, 31)];
}

function 计算HPACKHuffman字节长度(字符串) {
	const 字节 = new TextEncoder().encode(字符串);
	let 总位数 = 0;
	for (let i = 0; i < 字节.length; i++) {
		总位数 += HPACKHuffman码长[字节[i]];
	}
	return Math.ceil(总位数 / 8);
}

function 提取叉HTTPPadding值(request, 本机标识头, 本机标识键) {
	const 头值 = request.headers.get(本机标识头);
	if (头值) {
		try {
			const 解析URL = new URL(头值, 'https://x.invalid');
			const 查询值 = 解析URL.searchParams.get(本机标识键);
			if (查询值) return 查询值;
		} catch (e) { }
		return 头值;
	}
	const 请求URL = new URL(request.url);
	return 请求URL.searchParams.get(本机标识键) || '';
}

function 校验叉HTTPPadding(request, 本机标识头, 本机标识键) {
	const padding值 = 提取叉HTTPPadding值(request, 本机标识头, 本机标识键);
	if (!padding值) return true;
	const huffman长度 = 计算HPACKHuffman字节长度(padding值);
	return huffman长度 >= 98 && huffman长度 <= 1002;
}

const 叉HTTPBase62字符集 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function 生成叉HTTPPadding串(长度) {
	const 字符集长度 = 叉HTTPBase62字符集.length;
	let 结果 = '';
	for (let i = 0; i < 长度; i++) {
		结果 += 叉HTTPBase62字符集[Math.floor(Math.random() * 字符集长度)];
	}
	return 结果;
}

async function 处理叉HTTP请求(request, yourUUID, 反代上下文 = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const [本机标识头, 本机标识键] = 获取本机标识(yourUUID);
	if (!校验叉HTTPPadding(request, 本机标识头, 本机标识键)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const 首包 = await 读取叉HTTP首包(reader, yourUUID);
	if (!首包) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(首包.hostname) && 反代上下文.代理类型 === null) {
		try { reader.releaseLock() } catch (e) { }
		return new Response(构造本地204响应(首包.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store'
			}
		});
	}
	if (首包.isUDP && 首包.协议 !== 'trojan' && 首包.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	try {
		const 响应URL = new URL('https://x.invalid/');
		响应URL.searchParams.set(本机标识键, 生成叉HTTPPadding串(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(本机标识头, 响应URL.toString());
	} catch (e) { }

	if (首包.isUDP) return 处理叉HTTPUDP请求(首包, reader, request, 反代上下文, responseHeaders);

	try { reader.releaseLock() } catch (e) { }

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const abortController = new AbortController();
	let 已清理 = false;
	const 清理 = (reason) => {
		if (已清理) return;
		已清理 = true;
		try { abortController.abort(reason) } catch (e) { }
		失效TCP连接世代(remoteConnWrapper);
	};

	const 占位WS = { readyState: WebSocket.OPEN };

	let socket;
	try {
		socket = await forwardataTCP(首包.hostname, 首包.port, 首包.rawData, 占位WS, 首包.respHeader, remoteConnWrapper, yourUUID, request, 反代上下文, 首包.协议 === 'trojan', 首包.原始数据, true);
	} catch (err) {
		log(`[叉HTTP-Pipe] 连接失败: ${err?.message || err}`);
		清理(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		清理(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const 上行Promise = (async () => {
		const 上行合包器 = 创建上行Grain合包流();
		const 搬运Promise = 上行合包器.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void 搬运Promise.catch(清理);
		const 上行reader = request.body.getReader();
		const 取消上行reader = () => {
			try { 上行reader.cancel(abortController.signal.reason).catch(() => { }); } catch (e) { }
		};
		abortController.signal.addEventListener('abort', 取消上行reader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await 上行reader.read();
					if (done) break;
					if (value?.byteLength) await 上行合包器.写入(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', 取消上行reader);
				try { 上行reader.releaseLock() } catch (e) { }
			}
		} finally {
			try { await 上行合包器.结束() } catch (e) { }
		}
		await 搬运Promise;
	})();

	const 响应流 = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const 下行Promise = (async () => {
		const writer = 响应流.writable.getWriter();
		try {
			if (有效数据长度(首包.respHeader) > 0) await writer.write(首包.respHeader);
		} catch (error) {
			try { await writer.abort(error) } catch (e) { }
			throw error;
		} finally {
			try { writer.releaseLock() } catch (e) { }
		}
		await socket.readable.pipeTo(响应流.writable, { signal: abortController.signal });
	})();

	void 上行Promise.catch(清理);
	void 下行Promise.then(() => 清理(), 清理);
	void Promise.allSettled([上行Promise, 下行Promise]);

	return new Response(响应流.readable, { status: 200, headers: responseHeaders });
}

function 处理叉HTTPUDP请求(首包, reader, request, 反代上下文, responseHeaders) {
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let udpRespHeader = 首包.respHeader;
			const 叉桥 = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						已关闭 = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (已关闭) return;
					已关闭 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};
			let 转发失败 = false;
			try {
				if (首包.协议 === 'trojan') {
					木马UDP上下文.目标主机 = 首包.hostname;
					木马UDP上下文.目标端口 = 首包.port;
					if (木马UDP上下文.反代地址) await 转发木马UDP数据(首包.原始数据, 叉桥, 木马UDP上下文, request);
				}
				if (!(首包.协议 === 'trojan' && 木马UDP上下文.反代地址) && 首包.rawData?.byteLength) {
					if (首包.协议 === 'trojan') await 转发木马UDP数据(首包.rawData, 叉桥, 木马UDP上下文, request);
					else await forwardataudp(首包.rawData, 叉桥, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (首包.协议 === 'trojan') await 转发木马UDP数据(value, 叉桥, 木马UDP上下文, request);
					else await forwardataudp(value, 叉桥, udpRespHeader, request);
					udpRespHeader = null;
				}
			} catch (err) {
				转发失败 = true;
				log(`[叉HTTP转发] 处理失败: ${err?.message || err}`);
				closeSocketQuietly(叉桥);
			} finally {
				const 保持木马UDP反代下行 = !转发失败 && 首包.协议 === 'trojan' && 木马UDP上下文.反代地址 && 木马UDP上下文.反代Socket;
				if (!保持木马UDP反代下行) {
					try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
					closeSocketQuietly(叉桥);
				}
				try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function 有效数据长度(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function 失效TCP连接世代(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

function 开始TCP连接世代(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.停止并刷新?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}

async function 读取叉HTTP首包(reader, token) {
	const decoder = 魏烈思文本解码器;

	const 尝试解析魏烈思首包 = (data) => {
		const length = data.byteLength;
		if (length < 18) return { 状态: 'need_more' };
		if (!UUID字节匹配(data, 1, token)) return { 状态: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { 状态: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { 状态: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { 状态: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { 状态: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { 状态: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { 状态: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { 状态: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { 状态: 'invalid' };

		if (!hostname) return { 状态: 'invalid' };

		return {
			状态: 'ok',
			结果: {
				协议: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				原始数据: null,
			}
		};
	};

	const 尝试解析木马首包 = (data) => {
		const 密码哈希 = sha224(token);
		const 密码哈希字节 = new TextEncoder().encode(密码哈希);
		const length = data.byteLength;
		if (length < 58) return { 状态: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { 状态: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== 密码哈希字节[i]) return { 状态: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { 状态: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { 状态: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { 状态: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { 状态: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { 状态: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { 状态: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { 状态: 'invalid' };

		if (!hostname) return { 状态: 'invalid' };
		if (length < cursor + 4) return { 状态: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { 状态: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			状态: 'ok',
			结果: {
				协议: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				原始数据: data,
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const 当前数据 = buffer.subarray(0, offset);
		const 木马结果 = 尝试解析木马首包(当前数据);
		if (木马结果.状态 === 'ok') return { ...木马结果.结果, reader };

		const 魏烈思结果 = 尝试解析魏烈思首包(当前数据);
		if (魏烈思结果.状态 === 'ok') return { ...魏烈思结果.结果, reader };

		if (木马结果.状态 === 'invalid' && 魏烈思结果.状态 === 'invalid') return null;
	}

	const 最终数据 = buffer.subarray(0, offset);
	const 最终木马结果 = 尝试解析木马首包(最终数据);
	if (最终木马结果.状态 === 'ok') return { ...最终木马结果.结果, reader };
	const 最终魏烈思结果 = 尝试解析魏烈思首包(最终数据);
	if (最终魏烈思结果.状态 === 'ok') return { ...最终魏烈思结果.结果, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPC传输数据///////////////////////////////////////////////
async function 处理gRPC请求(request, yourUUID, 反代上下文 = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
	let isDnsQuery = false;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	let 判断是否是木马 = null;
	let 当前写入Socket = null;
	let 远端写入器 = null;
	let GRPC上行写入队列 = null;
	//log('[gRPC] 开始处理双向流');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const 下行缓存上限 = 下行Grain包字节;
	const 下行刷新间隔 = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let 已关闭 = false;
			let 发送队列 = [];
			let 队列字节数 = 0;
			let 刷新定时器 = null;
			let 刷新Microtask已排队 = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (已关闭) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytes数组 = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytes数组.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytes数组.push(remaining);
					const lenBytes = new Uint8Array(lenBytes数组);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					发送队列.push(frame);
					队列字节数 += frame.byteLength;
					安排刷新发送队列();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					刷新发送队列(true);
					已关闭 = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const 刷新发送队列 = (force = false) => {
				刷新Microtask已排队 = false;
				if (刷新定时器) {
					clearTimeout(刷新定时器);
					刷新定时器 = null;
				}
				if ((!force && 已关闭) || 队列字节数 === 0) return;
				const out = new Uint8Array(队列字节数);
				let offset = 0;
				for (const item of 发送队列) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				发送队列 = [];
				队列字节数 = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					已关闭 = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const 安排刷新发送队列 = () => {
				if (队列字节数 >= 下行缓存上限) {
					刷新发送队列();
					return;
				}
				if (刷新Microtask已排队 || 刷新定时器) return;
				刷新Microtask已排队 = true;
				queueMicrotask(() => {
					刷新Microtask已排队 = false;
					if (已关闭 || 队列字节数 === 0 || 刷新定时器) return;
					刷新定时器 = setTimeout(刷新发送队列, 下行刷新间隔);
				});
			};

			const 关闭连接 = () => {
				if (已关闭) return;
				GRPC上行写入队列?.清空();
				失效远端连接();
				刷新发送队列(true);
				已关闭 = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (刷新定时器) clearTimeout(刷新定时器);
				if (远端写入器) {
					try { 远端写入器.releaseLock() } catch (e) { }
					远端写入器 = null;
				}
				当前写入Socket = null;
				try { reader.releaseLock() } catch (e) { }
				try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			const 释放远端写入器 = () => {
				if (远端写入器) {
					try { 远端写入器.releaseLock() } catch (e) { }
					远端写入器 = null;
				}
				当前写入Socket = null;
			};

			const 上行写入队列 = GRPC上行写入队列 = 创建上行写入队列({
				获取写入器: () => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return null;
					if (socket !== 当前写入Socket) {
						释放远端写入器();
						当前写入Socket = socket;
						远端写入器 = socket.writable.getWriter();
					}
					return 远端写入器;
				},
				获取连接任务: () => remoteConnWrapper.connectingPromise,
				释放写入器: 释放远端写入器,
				重试连接: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				关闭连接,
				名称: 'gRPC上行'
			});

			const 写入远端 = async (payload, allowRetry = true) => {
				return 上行写入队列.写入并等待(payload, allowRetry);
			};

			let 转发失败 = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const 当前块 = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + 当前块.length);
					merged.set(pending, 0);
					merged.set(当前块, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varint有效 = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varint有效 = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varint有效) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (判断是否是木马) await 转发木马UDP数据(payload, grpcBridge, 木马UDP上下文, request);
							else await forwardataudp(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await 写入远端(payload))) throw new Error('Remote socket is not ready');
						} else {
							const 首包bytes = 数据转Uint8Array(payload);
							if (判断是否是木马 === null) 判断是否是木马 = 首包bytes.byteLength >= 58 && 首包bytes[56] === 0x0d && 首包bytes[57] === 0x0a;
							if (判断是否是木马) {
								const 解析结果 = 解析木马请求(首包bytes, yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = 解析结果;
								log(`[gRPC] 木马首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
									grpcBridge.send(构造本地204响应());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									木马UDP上下文.目标主机 = hostname;
									木马UDP上下文.目标端口 = port;
									if (木马UDP上下文.反代地址) await 转发木马UDP数据(首包bytes, grpcBridge, 木马UDP上下文, request);
									else if (有效数据长度(rawClientData) > 0) await 转发木马UDP数据(rawClientData, grpcBridge, 木马UDP上下文, request);
								} else {
									await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, 反代上下文, true, 首包bytes);
								}
							} else {
								判断是否是木马 = false;
								const 解析结果 = 解析魏烈思请求(首包bytes, yourUUID);
								if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid 魏烈思 request');
								const { port, hostname, version, isUDP, rawClientData } = 解析结果;
								log(`[gRPC] 魏烈思首包: ${hostname}:${port} | UDP: ${isUDP ? '是' : '否'}`);
								const respHeader = new Uint8Array([version, 0]);
								if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
									grpcBridge.send(构造本地204响应(respHeader));
									return;
								}
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								grpcBridge.send(respHeader);
								const rawData = rawClientData;
								if (isDnsQuery) {
									if (判断是否是木马) await 转发木马UDP数据(rawData, grpcBridge, 木马UDP上下文, request);
									else await forwardataudp(rawData, grpcBridge, null, request);
								}
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, 反代上下文);
							}
						}
					}
					刷新发送队列();
				}
				await 上行写入队列.等待空();
			} catch (err) {
				转发失败 = true;
				log(`[gRPC转发] 处理失败: ${err?.message || err}`);
			} finally {
				const 保持木马UDP反代下行 = !转发失败 && isDnsQuery && 判断是否是木马 && 木马UDP上下文.反代地址 && 木马UDP上下文.反代Socket;
				if (保持木马UDP反代下行) {
					上行写入队列.清空();
					失效远端连接();
					释放远端写入器();
					try { reader.releaseLock() } catch (e) { }
				} else {
					关闭连接();
				}
			}
		},
		cancel() {
			GRPC上行写入队列?.清空();
			失效远端连接();
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

function 是有效WS早期数据(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && UUID字节匹配(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function 解码WS早期数据(header, token) {
	if (!header) return null;
	if (header.length > WS早期数据最大头长度) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > WS早期数据最大字节) throw new Error('early data is too large');
	return 是有效WS早期数据(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WS传输数据///////////////////////////////////////////////
async function 处理WS请求(request, yourUUID, url, 反代上下文 = {}) {
	const WS套接字对 = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(WS套接字对);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const 失效远端连接 = () => 失效TCP连接世代(remoteConnWrapper);
	let isDnsQuery = false;
	let 判断是否是木马 = null;
	const 木马UDP上下文 = { 缓存: new Uint8Array(0), 反代地址: 反代上下文.木马反代地址 };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const SS模式禁用EarlyData = !!url.searchParams.get('enc');
	let WS上行写入队列 = null;
	let WS显式传输链 = Promise.resolve();
	let WS显式传输停止接收 = false, WS显式传输失败 = false, WS显式传输收尾已入队 = false;
	let WS显式队列字节 = 0, WS显式队列条目 = 0;
	let 判断协议类型 = null, 当前写入Socket = null, 远端写入器 = null;
	let ss上下文 = null, ss初始化任务 = null;
	let WS本地测速模式 = false, WS本地测速回包Socket = null;
	let WS本地测速请求缓存 = new Uint8Array(0);
	let WS本地测速首包响应头 = null;
	const WS本地测速请求上限 = 64 * 1024;

	const 发送WS本地测速响应 = async () => {
		if (!WS本地测速回包Socket) return;
		const respHeader = WS本地测速首包响应头;
		WS本地测速首包响应头 = null;
		await WebSocket发送并等待(WS本地测速回包Socket, 构造WS本地204响应(respHeader));
	};

	const 查找HTTP请求头结尾 = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const 处理WS本地测速数据 = async (data) => {
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return;
		if (WS本地测速请求缓存.byteLength + chunk.byteLength > WS本地测速请求上限) throw new Error('WS local speed-test request is too large');
		WS本地测速请求缓存 = 拼接字节数据(WS本地测速请求缓存, chunk);

		while (WS本地测速请求缓存.byteLength) {
			const headerEnd = 查找HTTP请求头结尾(WS本地测速请求缓存);
			if (headerEnd === -1) return;
			const headerText = 魏烈思文本解码器.decode(WS本地测速请求缓存.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > WS本地测速请求上限) throw new Error('WS local speed-test request body is too large');
			if (WS本地测速请求缓存.byteLength < requestLength) return;
			WS本地测速请求缓存 = WS本地测速请求缓存.slice(requestLength);
			await 发送WS本地测速响应();
		}
	};

	const 启用WS本地测速模式 = async (回包Socket, respHeader = null, 首请求数据 = null) => {
		WS本地测速模式 = true;
		WS本地测速回包Socket = 回包Socket;
		WS本地测速请求缓存 = new Uint8Array(0);
		WS本地测速首包响应头 = respHeader;
		if (有效数据长度(首请求数据) > 0) await 处理WS本地测速数据(首请求数据);
	};

	const 释放远端写入器 = () => {
		if (远端写入器) {
			try { 远端写入器.releaseLock() } catch (e) { }
			远端写入器 = null;
		}
		当前写入Socket = null;
	};

	const 上行写入队列 = WS上行写入队列 = 创建上行写入队列({
		获取写入器: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== 当前写入Socket) {
				释放远端写入器();
				当前写入Socket = socket;
				远端写入器 = socket.writable.getWriter();
			}
			return 远端写入器;
		},
		获取连接任务: () => remoteConnWrapper.connectingPromise,
		释放写入器: 释放远端写入器,
		重试连接: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		关闭连接: err => 处理WS显式传输错误(err),
		名称: 'WS上行'
	});

	const 写入远端 = async (chunk, allowRetry = true) => {
		return 上行写入队列.写入(chunk, allowRetry);
	};

	const 获取SS上下文 = async () => {
		if (ss上下文) return ss上下文;
		if (!ss初始化任务) {
			ss初始化任务 = (async () => {
				const 请求加密方式 = (url.searchParams.get('enc') || '').toLowerCase();
				const 首选加密配置 = SS支持加密配置[请求加密方式] || SS支持加密配置['aes-128-gcm'];
				const 入站候选加密配置 = [首选加密配置, ...Object.values(SS支持加密配置).filter(c => c.method !== 首选加密配置.method)];
				const 入站主密钥任务缓存 = new Map();
				const 取入站主密钥任务 = (config) => {
					if (!入站主密钥任务缓存.has(config.method)) 入站主密钥任务缓存.set(config.method, SS派生主密钥(yourUUID, config.keyLen));
					return 入站主密钥任务缓存.get(config.method);
				};
				const 入站状态 = {
					buffer: new Uint8Array(0),
					hasSalt: false,
					waitPayloadLength: null,
					decryptKey: null,
					nonceCounter: new Uint8Array(SSNonce长度),
					加密配置: null,
				};
				const 初始化入站解密状态 = async () => {
					const lengthCipherTotalLength = 2 + SSAEAD标签长度;
					const 最大盐长度 = Math.max(...入站候选加密配置.map(c => c.saltLen));
					const 最大对齐扫描字节 = 16;
					const 可扫描最大偏移 = Math.min(最大对齐扫描字节, Math.max(0, 入站状态.buffer.byteLength - (lengthCipherTotalLength + Math.min(...入站候选加密配置.map(c => c.saltLen)))));
					for (let offset = 0; offset <= 可扫描最大偏移; offset++) {
						for (const 加密配置 of 入站候选加密配置) {
							const 初始化最小长度 = offset + 加密配置.saltLen + lengthCipherTotalLength;
							if (入站状态.buffer.byteLength < 初始化最小长度) continue;
							const salt = 入站状态.buffer.subarray(offset, offset + 加密配置.saltLen);
							const lengthCipher = 入站状态.buffer.subarray(offset + 加密配置.saltLen, 初始化最小长度);
							const masterKey = await 取入站主密钥任务(加密配置);
							const decryptKey = await SS派生会话密钥(加密配置, masterKey, salt, ['decrypt']);
							const nonceCounter = new Uint8Array(SSNonce长度);
							try {
								const lengthPlain = await SSAEAD解密(decryptKey, nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > 加密配置.maxChunk) continue;
								if (offset > 0) log(`[SS入站] 检测到前导噪声 ${offset}B，已自动对齐`);
								if (加密配置.method !== 首选加密配置.method) log(`[SS入站] URL enc=${请求加密方式 || 首选加密配置.method} 与实际 ${加密配置.method} 不一致，已自动切换`);
								入站状态.buffer = 入站状态.buffer.subarray(初始化最小长度);
								入站状态.decryptKey = decryptKey;
								入站状态.nonceCounter = nonceCounter;
								入站状态.waitPayloadLength = payloadLength;
								入站状态.加密配置 = 加密配置;
								入站状态.hasSalt = true;
								return true;
							} catch (_) { }
						}
					}
					const 初始化失败判定长度 = 最大盐长度 + lengthCipherTotalLength + 最大对齐扫描字节;
					if (入站状态.buffer.byteLength >= 初始化失败判定长度) {
						throw new Error(`SS handshake decrypt failed (enc=${请求加密方式 || 'auto'}, candidates=${入站候选加密配置.map(c => c.method).join('/')})`);
					}
					return false;
				};
				const 入站解密器 = {
					async 输入(dataChunk) {
						const chunk = 数据转Uint8Array(dataChunk);
						if (chunk.byteLength > 0) 入站状态.buffer = 拼接字节数据(入站状态.buffer, chunk);
						if (!入站状态.hasSalt) {
							const 初始化成功 = await 初始化入站解密状态();
							if (!初始化成功) return [];
						}
						const plaintextChunks = [];
						while (true) {
							if (入站状态.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SSAEAD标签长度;
								if (入站状态.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = 入站状态.buffer.subarray(0, lengthCipherTotalLength);
								入站状态.buffer = 入站状态.buffer.subarray(lengthCipherTotalLength);
								const lengthPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > 入站状态.加密配置.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
								入站状态.waitPayloadLength = payloadLength;
							}
							const payloadCipherTotalLength = 入站状态.waitPayloadLength + SSAEAD标签长度;
							if (入站状态.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = 入站状态.buffer.subarray(0, payloadCipherTotalLength);
							入站状态.buffer = 入站状态.buffer.subarray(payloadCipherTotalLength);
							const payloadPlain = await SSAEAD解密(入站状态.decryptKey, 入站状态.nonceCounter, payloadCipher);
							plaintextChunks.push(payloadPlain);
							入站状态.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let 出站加密器 = null;
				const SS单批最大字节 = 32 * 1024;
				const 获取出站加密器 = async () => {
					if (出站加密器) return 出站加密器;
					if (!入站状态.加密配置) throw new Error('SS cipher is not negotiated');
					const 出站加密配置 = 入站状态.加密配置;
					const 出站主密钥 = await SS派生主密钥(yourUUID, 出站加密配置.keyLen);
					const 出站随机字节 = crypto.getRandomValues(new Uint8Array(出站加密配置.saltLen));
					const 出站加密密钥 = await SS派生会话密钥(出站加密配置, 出站主密钥, 出站随机字节, ['encrypt']);
					const 出站Nonce计数器 = new Uint8Array(SSNonce长度);
					let 随机字节已发送 = false;
					出站加密器 = {
						async 加密并发送(dataChunk, sendChunk) {
							const plaintextData = 数据转Uint8Array(dataChunk);
							if (!随机字节已发送) {
								await sendChunk(出站随机字节);
								随机字节已发送 = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(offset + 出站加密配置.maxChunk, plaintextData.byteLength);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, lengthPlain);
								const payloadCipher = await SSAEAD加密(出站加密密钥, 出站Nonce计数器, payloadPlain);
								const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return 出站加密器;
				};
				let SS发送队列 = Promise.resolve();
				const SS入队发送 = (chunk) => {
					SS发送队列 = SS发送队列.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const 已初始化出站加密器 = await 获取出站加密器();
						await 已初始化出站加密器.加密并发送(chunk, async (encryptedChunk) => {
							if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
								await WebSocket发送并等待(serverSock, encryptedChunk.buffer);
							}
						});
					}).catch((error) => {
						log(`[SS发送] 加密失败: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return SS发送队列;
				};
				const 回包Socket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = 数据转Uint8Array(data);
						if (chunk.byteLength <= SS单批最大字节) {
							return SS入队发送(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SS单批最大字节) {
							SS入队发送(chunk.subarray(i, Math.min(i + SS单批最大字节, chunk.byteLength)));
						}
						return SS发送队列;
					},
					close() {
						closeSocketQuietly(serverSock);
					}
				};
				ss上下文 = {
					入站解密器,
					回包Socket,
					首包已建立: false,
					目标主机: '',
					目标端口: 0,
				};
				return ss上下文;
			})().finally(() => { ss初始化任务 = null });
		}
		return ss初始化任务;
	};

	const 处理SS数据 = async (chunk) => {
		const 上下文 = await 获取SS上下文();
		let 明文块数组 = null;
		try {
			明文块数组 = await 上下文.入站解密器.输入(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
				log(`[SS入站] 解密失败，连接关闭: ${msg}`);
				closeSocketQuietly(serverSock);
				return;
			}
			throw err;
		}
		for (const 明文块 of 明文块数组) {
			if (WS本地测速模式) {
				await 处理WS本地测速数据(明文块);
				continue;
			}
			let 已写入 = false;
			try {
				已写入 = await 写入远端(明文块, false);
			} catch (err) {
				if ((/** @type {any} */ (err))?.isQueueOverflow) throw err;
				已写入 = false;
			}
			if (已写入) continue;
			if (上下文.首包已建立 && 上下文.目标主机 && 上下文.目标端口 > 0) {
				await forwardataTCP(上下文.目标主机, 上下文.目标端口, 明文块, 上下文.回包Socket, null, remoteConnWrapper, yourUUID, request, 反代上下文);
				continue;
			}
			const 明文数据 = 数据转Uint8Array(明文块);
			if (明文数据.byteLength < 3) throw new Error('invalid ss data');
			const addressType = 明文数据[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (明文数据.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
				hostname = `${明文数据[cursor]}.${明文数据[cursor + 1]}.${明文数据[cursor + 2]}.${明文数据[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (明文数据.byteLength < cursor + 1) throw new Error('invalid ss domain length');
				const domainLength = 明文数据[cursor];
				cursor += 1;
				if (明文数据.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
				hostname = SS文本解码器.decode(明文数据.subarray(cursor, cursor + domainLength));
				cursor += domainLength;
			} else if (addressType === 4) {
				if (明文数据.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(明文数据.buffer, 明文数据.byteOffset + cursor, 16);
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				cursor += 16;
			} else {
				throw new Error(`invalid ss addressType: ${addressType}`);
			}
			if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
			const port = (明文数据[cursor] << 8) | 明文数据[cursor + 1];
			cursor += 2;
			const rawClientData = 明文数据.subarray(cursor);
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(上下文.回包Socket, null, rawClientData);
				return;
			}
			上下文.首包已建立 = true;
			上下文.目标主机 = hostname;
			上下文.目标端口 = port;
			await forwardataTCP(hostname, port, rawClientData, 上下文.回包Socket, null, remoteConnWrapper, yourUUID, request, 反代上下文);
		}
	};

	const 处理WS入站数据 = async (chunk) => {
		let 当前块字节 = null;
		if (isDnsQuery) {
			if (判断是否是木马) return await 转发木马UDP数据(chunk, serverSock, 木马UDP上下文, request);
			return await forwardataudp(chunk, serverSock, null, request);
		}
		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (WS本地测速模式) {
			await 处理WS本地测速数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;

		if (判断协议类型 === null) {
			if (url.searchParams.get('enc')) 判断协议类型 = 'ss';
			else {
				当前块字节 = 当前块字节 || 数据转Uint8Array(chunk);
				const bytes = 当前块字节;
				判断协议类型 = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? '木马' : '魏烈思';
			}
			判断是否是木马 = 判断协议类型 === '木马';
			log(`[WS转发] 协议类型: ${判断协议类型} | 来自: ${url.host} | UA: ${request.headers.get('user-agent') || '未知'}`);
		}

		if (判断协议类型 === 'ss') {
			await 处理SS数据(chunk);
			return;
		}
		if (await 写入远端(chunk)) return;
		if (判断协议类型 === '木马') {
			const 解析结果 = 解析木马请求(chunk, yourUUID);
			if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = 解析结果;
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				木马UDP上下文.目标主机 = hostname;
				木马UDP上下文.目标端口 = port;
				if (木马UDP上下文.反代地址) return 转发木马UDP数据(当前块字节 || 数据转Uint8Array(chunk), serverSock, 木马UDP上下文, request);
				if (有效数据长度(rawClientData) > 0) return 转发木马UDP数据(rawClientData, serverSock, 木马UDP上下文, request);
				return;
			}
			await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, 反代上下文, true, 当前块字节 || 数据转Uint8Array(chunk));
		} else {
			判断是否是木马 = false;
			当前块字节 = 当前块字节 || 数据转Uint8Array(chunk);
			const bytes = 当前块字节;
			const 解析结果 = 解析魏烈思请求(bytes, yourUUID);
			if (解析结果?.hasError) throw new Error(解析结果.message || 'Invalid 魏烈思 request');
			const { port, hostname, version, isUDP, rawClientData } = 解析结果;
			const respHeader = new Uint8Array([version, 0]);
			if (isSpeedTestSite(hostname) && 反代上下文.代理类型 === null) {
				await 启用WS本地测速模式(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (判断是否是木马) return 转发木马UDP数据(rawData, serverSock, 木马UDP上下文, request);
				return forwardataudp(rawData, serverSock, respHeader, request);
			}
			await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, 反代上下文);
		}
	};

	const 处理WS显式传输错误 = (err) => {
		if (WS显式传输失败) return;
		WS显式传输失败 = true;
		WS显式传输停止接收 = true;
		WS显式队列字节 = 0;
		WS显式队列条目 = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WS转发] 连接结束: ${msg}`);
		} else {
			log(`[WS转发] 处理失败: ${msg}`);
		}
		上行写入队列.清空();
		释放远端写入器();
		失效远端连接();
		try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const 追加WS显式传输任务 = (任务) => {
		WS显式传输链 = WS显式传输链.then(任务).catch(处理WS显式传输错误);
		return WS显式传输链;
	};

	const 入队WS显式传输 = (data) => {
		if (WS显式传输停止接收 || WS显式传输失败) return;
		const chunkSize = Math.max(0, 有效数据长度(data));
		const nextBytes = WS显式队列字节 + chunkSize;
		const nextItems = WS显式队列条目 + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			处理WS显式传输错误(new Error(`[WS显式传输] 队列溢出: ${nextBytes}B/${nextItems}`));
			return;
		}
		WS显式队列字节 = nextBytes;
		WS显式队列条目 = nextItems;
		追加WS显式传输任务(async () => {
			WS显式队列字节 = Math.max(0, WS显式队列字节 - chunkSize);
			WS显式队列条目 = Math.max(0, WS显式队列条目 - 1);
			if (WS显式传输失败) return;
			await 处理WS入站数据(data);
		});
	};

	const 收尾WS显式传输 = () => {
		if (WS显式传输收尾已入队) return;
		WS显式传输收尾已入队 = true;
		WS显式传输停止接收 = true;
		追加WS显式传输任务(async () => {
			if (WS显式传输失败) return;
			await 上行写入队列.等待空();
			释放远端写入器();
			失效远端连接();
			try { 木马UDP上下文.反代Socket?.close() } catch (e) { }
		});
	};

	serverSock.addEventListener('message', (event) => {
		入队WS显式传输(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		收尾WS显式传输();
	});
	serverSock.addEventListener('error', (err) => {
		处理WS显式传输错误(err);
	});

	// SS 模式下禁用 sec-websocket-protocol early-data，避免把子协议值（如 "binary"）误当作 base64 数据注入首包导致 AEAD 解密失败。
	if (!SS模式禁用EarlyData && earlyDataHeader) {
		try {
			const bytes = 解码WS早期数据(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) 入队WS显式传输(bytes.buffer);
		} catch (error) {
			处理WS显式传输错误(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

const 木马文本解码器 = new TextDecoder();

function 解析木马反代地址(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) throw new Error('木马反代仅支持 host:port');
	let hostname = '', portText = '';
	if (raw.startsWith('[')) {
		const 匹配 = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!匹配) throw new Error('无效的 IPv6 木马反代地址');
		hostname = 匹配[1];
		portText = 匹配[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('木马反代仅支持 host:port');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('无效的木马反代端口');
	return { hostname, port };
}

async function 连接木马反代(首包数据, TCP连接, 木马反代目标) {
	if (!木马反代目标) throw new Error('trojan fallback is not configured');
	const socket = TCP连接({ hostname: stripIPv6Brackets(木马反代目标.hostname), port: 木马反代目标.port });
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (有效数据长度(首包数据) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(数据转Uint8Array(首包数据));
		}
		return socket;
	} catch (error) {
		try { socket?.close?.() } catch (e) { }
		throw error;
	} finally {
		try { writer?.releaseLock() } catch (e) { }
	}
}

function 提取木马反代握手数据(首包数据, rawData) {
	const 首包 = 数据转Uint8Array(首包数据);
	const payload = 数据转Uint8Array(rawData);
	if (!payload.byteLength) return 首包;
	const 握手长度 = 首包.byteLength - payload.byteLength;
	if (握手长度 <= 0) return 首包;
	for (let i = 0; i < payload.byteLength; i++) {
		if (首包[握手长度 + i] !== payload[i]) return 首包;
	}
	return 首包.subarray(0, 握手长度);
}

async function 转发木马UDP反代数据(chunk, webSocket, 上下文, request) {
	const data = 数据转Uint8Array(chunk);
	if (!上下文.反代Socket) {
		const TCP连接 = 创建请求TCP连接器(request);
		const socket = await 连接木马反代(data, TCP连接, 上下文.反代地址);
		上下文.反代Socket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = 上下文.反代Socket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

function 解析木马请求(buffer, passwordPlainText) {
	const data = 数据转Uint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = 木马文本解码器.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}

const UUID字节缓存 = new Map();
const 魏烈思文本解码器 = new TextDecoder();

function 读取十六进制半字节(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function 获取UUID字节(uuid) {
	const key = String(uuid || '');
	let cached = UUID字节缓存.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = 读取十六进制半字节(clean.charCodeAt(i * 2));
		const low = 读取十六进制半字节(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUID字节缓存.size >= 32) UUID字节缓存.clear();
	UUID字节缓存.set(key, bytes);
	return bytes;
}

function UUID字节匹配(data, offset, uuid) {
	const expected = 获取UUID字节(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function 解析魏烈思请求(chunk, token) {
	const data = 数据转Uint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUID字节匹配(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = 魏烈思文本解码器.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

const SS支持加密配置 = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

const SSAEAD标签长度 = 16, SSNonce长度 = 12;
const SS子密钥信息 = new TextEncoder().encode('ss-subkey');
const SS文本编码器 = new TextEncoder(), SS文本解码器 = new TextDecoder(), SS主密钥缓存 = new Map();

function 数据转Uint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function 拼接字节数据(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(数据转Uint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function 转发木马UDP数据(chunk, webSocket, 上下文, request) {
	const 当前块 = 数据转Uint8Array(chunk);
	if (上下文?.反代地址) return 转发木马UDP反代数据(当前块, webSocket, 上下文, request);
	const 缓存块 = 上下文?.缓存 instanceof Uint8Array ? 上下文.缓存 : new Uint8Array(0);
	const input = 缓存块.byteLength ? 拼接字节数据(缓存块, 当前块) : 当前块;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const 地址端口头 = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNS查询 = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNS查询 = new Uint8Array(payload.byteLength + 2);
			tcpDNS查询[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNS查询[1] = payload.byteLength & 0xff;
			tcpDNS查询.set(payload, 2);
		}

		const dns响应上下文 = { 缓存: new Uint8Array(0) };
		await forwardataudp(tcpDNS查询, webSocket, null, request, (dnsRespChunk) => {
			const 当前响应块 = 数据转Uint8Array(dnsRespChunk);
			const 响应输入 = dns响应上下文.缓存.byteLength ? 拼接字节数据(dns响应上下文.缓存, 当前响应块) : 当前响应块;
			const 响应帧列表 = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= 响应输入.byteLength) {
				const dnsLen = (响应输入[responseCursor] << 8) | 响应输入[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > 响应输入.byteLength) break;
				const dnsPayload = 响应输入.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(地址端口头.byteLength + 4 + dnsPayload.byteLength);
				frame.set(地址端口头, 0);
				frame[地址端口头.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[地址端口头.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[地址端口头.byteLength + 2] = 0x0d;
				frame[地址端口头.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, 地址端口头.byteLength + 4);
				响应帧列表.push(frame);
				responseCursor = dnsEnd;
			}
			dns响应上下文.缓存 = 响应输入.slice(responseCursor);
			return 响应帧列表.length ? 响应帧列表 : new Uint8Array(0);
		});
	}

	if (上下文) 上下文.缓存 = input.slice(cursor);
}

function SS递增Nonce计数器(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function SS派生主密钥(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (SS主密钥缓存.has(cacheKey)) return SS主密钥缓存.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = SS文本编码器.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = 拼接字节数据(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	SS主密钥缓存.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { SS主密钥缓存.delete(cacheKey); throw error }
}

async function SS派生会话密钥(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = 拼接字节数据(prev, SS子密钥信息, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function SSAEAD加密(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(ct);
}

async function SSAEAD解密(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SS递增Nonce计数器(nonceCounter);
	return new Uint8Array(pt);
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, 反代上下文 = {}, 允许木马反代 = false, 木马反代首包数据 = null, 仅建立连接 = false) {
	const ctx反代IP = 反代上下文.反代IP || '';
	const ctx代理类型 = 反代上下文.代理类型 !== undefined ? 反代上下文.代理类型 : null;
	const ctx代理全局 = 反代上下文.代理全局 !== undefined ? 反代上下文.代理全局 : false;
	const ctx代理参数 = 反代上下文.代理参数 || {};
	const ctx反代兜底 = 反代上下文.反代兜底 !== undefined ? 反代上下文.反代兜底 : true;
	let 反代数组索引 = 0;
	log(`[TCP转发] 目标: ${host}:${portNum} | 反代IP: ${ctx反代IP} | 反代兜底: ${ctx反代兜底 ? '是' : '否'} | 反代类型: ${ctx代理类型 || 'proxyip'} | 全局: ${ctx代理全局 ? '是' : '否'}`);
	const 连接超时毫秒 = 1000;
	let 已通过代理发送首包 = false;
	const TCP连接 = 创建请求TCP连接器(request);
	const 使用木马反代 = 允许木马反代 && (反代上下文.木马反代地址 || null);
	const 木马反代目标 = 使用木马反代 ? 反代上下文.木马反代地址 : null;
	const 木马反代握手数据 = 使用木马反代 ? 提取木马反代握手数据(木马反代首包数据, rawData) : null;
	let 待发送响应头 = respHeader;
	const 取出响应头 = () => {
		const header = 待发送响应头;
		待发送响应头 = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const 安装当前连接 = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const 连接仍有效 = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		if (仅建立连接) return socket;
		connectStreams(socket, ws, 取出响应头, retryFunc, 连接仍有效, remoteConnWrapper).catch(err => {
			if (!连接仍有效()) return;
			log(`[TCP下行] 处理失败: ${err?.message || err}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function 等待连接建立(remoteSock, timeoutMs = 连接超时毫秒) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('连接超时')), timeoutMs))
		]);
	}

	async function 打开TCP连接(address, port) {
		const remoteSock = TCP连接({ hostname: address, port });
		try {
			await 等待连接建立(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function 写入首包(remoteSock, data) {
		if (有效数据长度(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(数据转Uint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function 并发打开候选连接(候选列表) {
		if (候选列表.length === 1) {
			const 候选 = 候选列表[0];
			return { socket: await 打开TCP连接(候选.hostname, 候选.port), candidate: 候选 };
		}
		const attempts = 候选列表.map(候选 => 打开TCP连接(候选.hostname, 候选.port).then(socket => ({ socket, candidate: 候选 })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function 构建预加载竞速候选列表(address, port) {
		if (!预加载竞速拨号 || isIPHostname(address)) return null;
		log(`[TCP直连] 预加载竞速拨号开启，开始并发查询 ${address} 的 A/AAAA 记录`);
		const [aRecords, aaaaRecords] = await Promise.all([
			DoH查询(address, 'A'),
			DoH查询(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const 拨号上限 = Math.max(1, TCP并发拨号数 | 0);
		const ipList = ipv4List.length >= 拨号上限
			? ipv4List.slice(0, 拨号上限)
			: ipv4List.concat(ipv6List.slice(0, 拨号上限 - ipv4List.length));
		const 使用记录类型 = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log(`[TCP直连] ${address} 的 A/AAAA 未获得可用解析结果，预加载竞速不可用，回退到原始 hostname 直连。`);
			return null;
		}
		const 选中IP列表 = ipList;
		log(`[TCP直连] ${address} A记录:${ipv4List.length} AAAA记录:${ipv6List.length}，使用${使用记录类型}记录，竞速拨号 ${选中IP列表.length}/${拨号上限}: ${选中IP列表.join(', ')}`);
		return 选中IP列表.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, 启用预加载 = false) {
		const 预加载候选列表 = 启用预加载 ? await 构建预加载竞速候选列表(address, port) : null;
		const 候选列表 = 预加载候选列表 || Array.from({ length: TCP并发拨号数 }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(预加载候选列表
			? `[TCP直连] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`
			: `[TCP直连] 并发尝试 ${候选列表.length} 路: ${address}:${port}`);
		let socket = null;
		try {
			const 连接结果 = await 并发打开候选连接(候选列表);
			socket = 连接结果.socket;
			if (预加载候选列表) {
				const winner = 连接结果.candidate;
				log(`[TCP直连] 预加载竞速结果: ${winner.hostname}:${winner.port} 胜出，源域名: ${winner.resolvedFrom || address}`);
			}
			await 写入首包(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (预加载候选列表) log(`[TCP直连] 预加载竞速失败: ${err.message || err}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, 所有反代数组 = null, 启用反代失败兜底 = true) {
		if (所有反代数组 && 所有反代数组.length > 0) {
			const 实际并发数 = Math.max(1, Math.floor(Number(反代并发拨号数) || 1));
			for (let i = 0; i < 所有反代数组.length; i += 实际并发数) {
				const 候选列表 = [];
				for (let j = 0; j < 实际并发数 && i + j < 所有反代数组.length; j++) {
					const 索引 = (反代数组索引 + i + j) % 所有反代数组.length;
					const [反代地址, 反代端口] = 所有反代数组[索引];
					候选列表.push({ hostname: 反代地址, port: 反代端口, index: 索引 });
				}
				let socket = null, candidate = null;
				try {
					log(`[反代连接] 并发尝试 ${候选列表.length} 路: ${候选列表.map(候选 => `${候选.hostname}:${候选.port}`).join(', ')}`);
					const 连接结果 = await 并发打开候选连接(候选列表);
					socket = 连接结果.socket;
					candidate = 连接结果.candidate;
					await 写入首包(socket, data);
					log(`[反代连接] 成功连接到: ${candidate.hostname}:${candidate.port} (索引: ${candidate.index})`);
					反代数组索引 = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[反代连接] 本批连接失败: ${err.message || err}`);
				}
			}
		}

		if (启用反代失败兜底) return connectDirect(address, port, data, false);
		else {
			throw new Error('[反代连接] 所有反代连接失败，且未启用反代兜底，连接终止。');
		}
	}

	async function connecttoPry(允许发送首包 = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: 当前连接世代, downlinkDrain } = 开始TCP连接世代(remoteConnWrapper);

		let 本次发送首包 = false, 本次首包数据 = null;
		if (使用木马反代) {
			if (允许发送首包 && !已通过代理发送首包 && 有效数据长度(木马反代首包数据) > 0) {
				本次首包数据 = 木马反代首包数据;
				本次发送首包 = 有效数据长度(rawData) > 0;
			} else {
				本次首包数据 = 木马反代握手数据;
			}
		} else {
			本次发送首包 = 允许发送首包 && !已通过代理发送首包 && 有效数据长度(rawData) > 0;
			本次首包数据 = 本次发送首包 ? rawData : null;
		}

		const 当前连接任务 = (async () => {
			let newSocket = null;
			try {
				if (使用木马反代) {
					log(`[木马反代] 代理到: ${host}:${portNum}`);
					newSocket = await 连接木马反代(本次首包数据, TCP连接, 木马反代目标);
				} else if (ctx代理类型 === 'socks5') {
					log(`[SOCKS5代理] 代理到: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, 本次首包数据, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'http') {
					log(`[HTTP代理] 代理到: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, 本次首包数据, false, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'https') {
					log(`[HTTPS代理] 代理到: ${host}:${portNum}`);
					newSocket = isIPHostname(ctx代理参数.hostname)
						? await httpsConnect(host, portNum, 本次首包数据, TCP连接, ctx代理参数)
						: await httpConnect(host, portNum, 本次首包数据, true, TCP连接, ctx代理参数);
				} else if (ctx代理类型 === 'turn') {
					log(`[TURN代理] 代理到: ${host}:${portNum}`);
					newSocket = await turnConnect(ctx代理参数, host, portNum, TCP连接);
					if (有效数据长度(本次首包数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(数据转Uint8Array(本次首包数据)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctx代理类型 === 'sstp') {
					log(`[SSTP代理] 代理到: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctx代理参数, host, portNum, TCP连接);
					if (有效数据长度(本次首包数据) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(数据转Uint8Array(本次首包数据)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else {
					log(`[反代连接] 代理到: ${host}:${portNum}`);
					const 所有反代数组 = await 解析地址端口(ctx反代IP, host, yourUUID);
					newSocket = await connectProxyIP(`${特征码字典[0]}.tp1.${特征码字典[2]}.xyz`, 1, 本次首包数据, 所有反代数组, ctx反代兜底);
				}
				await 安装当前连接(newSocket, 当前连接世代, downlinkDrain);
				if (本次发送首包) 已通过代理发送首包 = true;
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === 当前连接世代) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
			}
		})();

		remoteConnWrapper.connectingPromise = 当前连接任务;
		try {
			await 当前连接任务;
		} finally {
			if (remoteConnWrapper.connectingPromise === 当前连接任务) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);

	if (ctx代理类型 && (ctx代理全局 || SOCKS5白名单.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[TCP转发] 启用 SOCKS5/HTTP/HTTPS/TURN/SSTP 全局代理`);
		try {
			await connecttoPry();
			if (仅建立连接) return remoteConnWrapper.socket;
		} catch (err) {
			log(`[TCP转发] SOCKS5/HTTP/HTTPS/TURN/SSTP 代理连接失败: ${err.message}`);
			throw err;
		}
	} else {
		let 直连世代 = remoteConnWrapper.generation;
		try {
			log(`[TCP转发] 尝试直连到: ${host}:${portNum}`);
			const 世代连接 = 开始TCP连接世代(remoteConnWrapper);
			直连世代 = 世代连接.generation;
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			await 安装当前连接(initialSocket, 直连世代, 世代连接.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== 直连世代 || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (仅建立连接) return initialSocket;
		} catch (err) {
			log(`[TCP转发] 直连 ${host}:${portNum} 失败: ${err.message}`);
			if (remoteConnWrapper.generation !== 直连世代) throw err;
			if (err instanceof Error && err.name === '预加载解析为空') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			await connecttoPry();
			if (仅建立连接) return remoteConnWrapper.socket;
		}
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader, request, 响应封装器 = null) {
	const 请求数据 = 数据转Uint8Array(udpChunk);
	const 请求字节数 = 请求数据.byteLength;
	log(`[UDP转发] 收到 DNS 请求: ${请求字节数}B -> 8.8.4.4:53`);
	try {
		const TCP连接 = 创建请求TCP连接器(request);
		const tcpSocket = TCP连接({ hostname: '8.8.4.4', port: 53 });
		let 魏烈思Header = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(请求数据);
		log(`[UDP转发] DNS 请求已写入上游: ${请求字节数}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const 原始响应 = 数据转Uint8Array(chunk);
				log(`[UDP转发] 收到 DNS 响应: ${原始响应.byteLength}B`);
				const 封装结果 = 响应封装器 ? await 响应封装器(原始响应) : 原始响应;
				const 发送片段列表 = Array.isArray(封装结果) ? 封装结果 : [封装结果];
				if (!发送片段列表.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of 发送片段列表) {
					const 转发响应 = 数据转Uint8Array(fragment);
					if (!转发响应.byteLength) continue;
					if (魏烈思Header) {
						const response = new Uint8Array(魏烈思Header.length + 转发响应.byteLength);
						response.set(魏烈思Header, 0);
						response.set(转发响应, 魏烈思Header.length);
						await WebSocket发送并等待(webSocket, response.buffer);
						魏烈思Header = null;
					} else {
						await WebSocket发送并等待(webSocket, 转发响应);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDP转发] DNS 转发失败: ${error?.message || error}`);
	}
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function WebSocket发送并等待(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function 创建Grain收纳器(容量, 复制合包结果 = false) {
	let 队列 = [];
	let 头 = 0;
	let 字节数 = 0;
	let 合包缓冲 = null;

	const 为空 = () => 头 >= 队列.length;
	const 压缩 = () => {
		if (头 > 32 && 头 * 2 >= 队列.length) {
			队列 = 队列.slice(头);
			头 = 0;
		}
	};
	const 取出 = () => {
		if (为空()) return null;
		const item = 队列[头];
		队列[头++] = undefined;
		字节数 -= item.chunk.byteLength;
		压缩();
		return item;
	};

	return {
		get 字节数() { return 字节数 },
		get 条目数() { return 队列.length - 头 },
		get 为空() { return 为空() },
		清空(处理项目 = null) {
			if (处理项目) {
				for (let i = 头; i < 队列.length; i++) {
					if (队列[i]) 处理项目(队列[i]);
				}
			}
			队列 = [];
			头 = 0;
			字节数 = 0;
		},
		收纳(item) {
			if (!item?.chunk?.byteLength) return false;
			队列.push(item);
			字节数 += item.chunk.byteLength;
			return true;
		},
		合包() {
			const first = 取出();
			if (!first) return null;
			const items = [first];
			if (为空() || first.chunk.byteLength >= 容量) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = 头;
			while (end < 队列.length) {
				const nextBytes = totalBytes + 队列[end].chunk.byteLength;
				if (nextBytes > 容量) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === 头) return { chunk: first.chunk, items };

			const output = (合包缓冲 ||= new Uint8Array(容量));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (头 < end) {
				const next = 队列[头];
				队列[头++] = undefined;
				字节数 -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			压缩();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: 复制合包结果 ? bundled.slice() : bundled, items };
		}
	};
}

function 创建上行Grain合包流(目标字节 = 上行合包目标字节) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const 缓冲 = new Uint8Array(目标字节);
	let 缓冲长度 = 0;
	let 定时器 = null;
	let 在途写 = null;
	let 冲刷链 = Promise.resolve();

	const 清理定时器 = () => {
		if (定时器) {
			clearTimeout(定时器);
			定时器 = null;
		}
	};

	const 串行写 = async (chunk) => {
		if (在途写) await 在途写;
		在途写 = writer.write(chunk);
		try { await 在途写 } finally { 在途写 = null; }
	};

	const 冲刷 = async () => {
		if (缓冲长度) {
			const chunk = 缓冲.slice(0, 缓冲长度);
			缓冲长度 = 0;
			await 串行写(chunk);
		}
	};

	const 排队冲刷 = () => {
		冲刷链 = 冲刷链.then(() => 冲刷()).catch(() => { });
	};

	const 启动定时器 = () => {
		if (定时器) return;
		定时器 = setTimeout(() => {
			定时器 = null;
			排队冲刷();
		}, 1);
	};

	return {
		readable: identity.readable,
		写入: async (chunk) => {
			const data = 数据转Uint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= 目标字节) {
				清理定时器();
				if (缓冲长度) await 冲刷();
				await 串行写(data);
				return;
			}
			if (缓冲长度 + data.byteLength >= 目标字节) {
				const output = new Uint8Array(缓冲长度 + data.byteLength);
				output.set(缓冲.subarray(0, 缓冲长度), 0);
				output.set(data, 缓冲长度);
				缓冲长度 = 0;
				清理定时器();
				await 串行写(output);
			} else {
				缓冲.set(data, 缓冲长度);
				缓冲长度 += data.byteLength;
				启动定时器();
			}
		},
		结束: async () => {
			清理定时器();
			try {
				await 冲刷链;
				await 冲刷();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

function 创建上行写入队列({ 获取写入器, 获取连接任务 = null, 释放写入器, 重试连接, 关闭连接, 名称 = '上行队列' }) {
	const grain = 创建Grain收纳器(上行合包目标字节);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.字节数 || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${名称}: queue closed`) : null);
		if (closeErr) {
			grain.清空(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.清空();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.合包();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const 等待可用写入器 = async () => {
		let writer = 获取写入器();
		if (writer) return writer;
		const connectionTask = 获取连接任务?.();
		if (connectionTask) await connectionTask;
		return 获取写入器();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await 等待可用写入器();
					if (closed) break;
					if (!writer) throw new Error(`${名称}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						释放写入器?.();
						if (closed) break;
						if (!item.allowRetry || typeof 重试连接 !== 'function') throw err;
						await 重试连接();
						if (closed) break;
						writer = 获取写入器();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${名称}] 写入失败: ${err?.message || err}`);
			try { 关闭连接?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.为空) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// 首包解析阶段既没有 writer 也没有连接任务；返回 false 交给上层继续协议解析。
		// 已建立会话的重拨阶段则先收纳，drain 会等待新 writer，避免数据被误当成首包。
		if (!获取写入器() && !获取连接任务?.()) return false;
		const chunk = 数据转Uint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.字节数 + chunk.byteLength;
		const nextItems = grain.条目数 + 1;
		if (nextBytes > 上行队列最大字节 || nextItems > 上行队列最大条目) {
			closed = true;
			const err = Object.assign(new Error(`${名称}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${名称}] 队列超限，关闭连接`);
			try { 关闭连接?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.收纳({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		写入(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		写入并等待(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async 等待空() {
			if (!grain.字节数 && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		清空() {
			closed = true;
			clear();
		}
	};
}

function 创建下行Grain发送器(webSocket, headerData = null, isActive = null) {
	const packetCap = 下行Grain包字节;
	const tailBytes = 下行Grain尾部阈值;
	const grain = 创建Grain收纳器(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const 获取响应头 = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let 强制排空 = false;
	let 停止已开始 = false;
	let 活动发送数 = 0;
	let 活动直发数 = 0;
	let 活动发送错误 = null;
	let 活动发送等待者 = [];
	const 等待活动发送完成 = () => {
		if (!活动发送数 && !活动直发数) return Promise.resolve();
		return new Promise(resolve => 活动发送等待者.push(resolve));
	};
	const 标记发送完成 = () => {
		if (活动发送数 || 活动直发数 || !活动发送等待者.length) return;
		const resolvers = 活动发送等待者;
		活动发送等待者 = [];
		for (const resolve of resolvers) resolve();
	};
	const 检查活动发送错误 = () => {
		if (!活动发送错误) return;
		const err = 活动发送错误;
		grain.清空();
		throw err;
	};
	const 当前发送器有效 = () => 强制排空 || !isActive || isActive();
	const 关闭活动连接 = () => {
		if (当前发送器有效()) closeSocketQuietly(webSocket);
	};

	const 发送原始块 = async (chunk) => {
		if (!当前发送器有效()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = 附加响应头(chunk);
		await WebSocket发送并等待(webSocket, chunk);
	};

	const 串行发送原始块 = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = 发送原始块(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const 附加响应头 = (chunk) => {
		const responseHeader = 获取响应头();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!当前发送器有效()) {
			grain.清空();
			return;
		}
		const 发送任务 = (async () => {
			for (; ;) {
				if (!当前发送器有效()) {
					grain.清空();
					break;
				}
				const packed = grain.合包();
				if (!packed) break;
				await 串行发送原始块(packed.chunk);
			}
		})();
		flushPromise = 发送任务.catch(err => {
			活动发送错误 ||= err;
			throw err;
		}).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!当前发送器有效()) {
			grain.清空();
			return;
		}
		if (grain.为空 || flushTimer) return;
		if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
			flush().catch(关闭活动连接);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!当前发送器有效()) {
				grain.清空();
				return;
			}
			if (grain.为空) return;
			if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) {
				flush().catch(关闭活动连接);
				return;
			}
			if (waitRounds < 下行Grain最大等待轮次 && (generation !== scheduledGeneration || grain.字节数 < 下行Grain低水位字节)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(关闭活动连接);
		}, 1);
	};

	return {
		async 直接发送(data) {
			if (停止已开始 || !当前发送器有效()) return;
			活动直发数++;
			try {
				const chunk = 数据转Uint8Array(data);
				if (!chunk.byteLength) return;
				await 串行发送原始块(chunk);
			} catch (err) {
				活动发送错误 ||= err;
				throw err;
			} finally {
				活动直发数--;
				标记发送完成();
			}
		},
		async 发送(data) {
			if (停止已开始 || !当前发送器有效()) return;
			活动发送数++;
			try {
				const chunk = 数据转Uint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.为空 && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await 串行发送原始块(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.字节数, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.收纳({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.字节数 >= packetCap || packetCap - grain.字节数 < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				活动发送错误 ||= err;
				throw err;
			} finally {
				活动发送数--;
				标记发送完成();
			}
		},
		flush,
		async 停止并刷新() {
			if (停止已开始) {
				await 等待活动发送完成();
				while (directSendPromise) await directSendPromise;
				检查活动发送错误();
				await flush();
				return;
			}
			停止已开始 = true;
			强制排空 = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await 等待活动发送完成();
			while (directSendPromise) await directSendPromise;
			检查活动发送错误();
			await flush();
		}
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const BYOB单次读取上限 = 64 * 1024;
	const 当前连接仍有效 = () => !isCurrentSocket || isCurrentSocket();
	const 下行发送器 = 创建下行Grain发送器(webSocket, header, 当前连接仍有效);
	header = null;
	const 下行控制器 = { 停止并刷新: () => 下行发送器.停止并刷新() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = 下行控制器;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!当前连接仍有效()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
				} else {
					await 下行发送器.发送(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB单次读取上限);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB单次读取上限));
				if (!当前连接仍有效()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= 下行Grain包字节) {
					await 下行发送器.flush();
					await 下行发送器.直接发送(value);
					readBuffer = new ArrayBuffer(BYOB单次读取上限);
				} else {
					await 下行发送器.发送(value.slice());
					readBuffer = value.buffer.byteLength >= BYOB单次读取上限 ? value.buffer : new ArrayBuffer(BYOB单次读取上限);
				}
			}
		}
		if (当前连接仍有效()) await 下行发送器.flush();
	} catch (err) { readError = err }
	finally {
		if (当前连接仍有效() && webSocket.readyState === WebSocket.OPEN) {
			try { await 下行发送器.停止并刷新() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === 下行控制器) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && 当前连接仍有效()) {
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!当前连接仍有效()) return;
	if (readError) log(`[TCP下行] 读取失败: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function 构造本地204响应(respHeader = null) {
	const 本地204响应 = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (有效数据长度(respHeader) === 0) return 本地204响应;
	const 协议响应头 = 数据转Uint8Array(respHeader);
	const response = new Uint8Array(协议响应头.byteLength + 本地204响应.byteLength);
	response.set(协议响应头, 0);
	response.set(本地204响应, 协议响应头.byteLength);
	log(`[TCP转发] 构造本地204响应: ${response.byteLength}B`);
	return response;
}

function 构造WS本地204响应(respHeader = null) {
	const WS本地204响应 = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (有效数据长度(respHeader) === 0) return WS本地204响应;
	const 协议响应头 = 数据转Uint8Array(respHeader);
	const response = new Uint8Array(协议响应头.byteLength + WS本地204响应.byteLength);
	response.set(协议响应头, 0);
	response.set(WS本地204响应, 协议响应头.byteLength);
	return response;
}

///////////////////////////////////////////////////////SOCKS5/HTTP函数///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData, TCP连接, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = TCP连接({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (有效数据长度(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, HTTPS代理 = false, TCP连接, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = HTTPS代理
		? TCP连接({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: TCP连接({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPS代理) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPS代理 ? 'HTTPS' : 'HTTP'} 代理在返回 CONNECT 响应前关闭连接`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (有效数据长度(initialData) > 0) {
			const 远端写入器 = socket.writable.getWriter();
			await 远端写入器.write(initialData);
			远端写入器.releaseLock();
		}

		// CONNECT 响应头后可能夹带隧道数据，先回灌到可读流，避免首包被吞。
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpsConnect(targetHost, targetPort, initialData, TCP连接, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const 打开HTTPS代理TLS = async (allowChacha = false) => {
		const proxySocket = TCP连接({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await socket.handshake();
			log(`[HTTPS代理] TLS版本: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return socket;
		} catch (error) {
			try { proxySocket.close() } catch (e) { }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await 打开HTTPS代理TLS(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
			log(`[HTTPS代理] AES-GCM TLS 握手失败，回退 ChaCha20 兼容模式: ${error?.message || error}`);
			tlsSocket = await 打开HTTPS代理TLS(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('HTTPS 代理在返回 CONNECT 响应前关闭连接');
			responseBuffer = 拼接字节数据(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('HTTPS 代理 CONNECT 响应头过长或无效');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (有效数据长度(initialData) > 0) await tlsSocket.write(数据转Uint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false, resolveClosed, rejectClosed;
		const settleClosed = (settle, value) => {
			if (!closedSettled) {
				closedSettled = true;
				settle(value);
			}
		};
		const closed = new Promise((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = () => {
			try { tlsSocket.close() } catch (e) { }
			settleClosed(resolveClosed);
		};
		const readable = new ReadableStream({
			async start(controller) {
				try {
					if (有效数据长度(bufferedData) > 0) controller.enqueue(bufferedData);
					while (true) {
						const data = await tlsSocket.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try { controller.close() } catch (e) { }
					settleClosed(resolveClosed);
				} catch (error) {
					try { controller.error(error) } catch (e) { }
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			}
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(数据转Uint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close() } catch (e) { }
		throw error;
	}
}

function 创建请求TCP连接器(request) {
	const 请求对象 = /** @type {any} */ (request);
	const fetcher = 请求对象?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = 数据转Uint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = 数据转Uint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		let clientCertRequested = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		if (clientCertRequested) {
			const emptyCertificate = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0));
			this.recordHandshake(emptyCertificate), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, emptyCertificate))
		}
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		let clientCertRequested = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					this.recordHandshake(message.raw), clientCertRequested = !0;
					break;
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		let clientFlightHandshake = EMPTY_BYTES;
		if (clientCertRequested) clientFlightHandshake = buildHandshakeMessage(HANDSHAKE_TYPE_CERTIFICATE, tlsBytes(0, 0, 0, 0)), this.recordHandshake(clientFlightHandshake);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFlightHandshake, clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = 数据转Uint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

//////////////////////////////////////////////////turnConnect///////////////////////////////////////////////
const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003, ALLOCATE_SUCCESS: 0x0103, ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008, CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a, CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b, CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008, ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012, REALM: 0x0014, NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019, CONNECTION_ID: 0x002a
};

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function turnStunPadding(length) {
	return -length & 3;
}

function createTurnStunAttribute(type, value) {
	const body = 数据转Uint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = 拼接字节数据(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return 拼接字节数据(header, body);
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return 拼接字节数据(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = 有效数据长度(bufferedData) ? 数据转Uint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = 拼接字节数据(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function turnConnect(proxy, targetHost, targetPort, TCP连接) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	/** @type {string | null} */
	let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await DoH查询(resolvedTargetHost, 'A');
		const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null, dataSocket = null, controlWriter = null, controlReader = null, dataWriter = null, dataReader = null, dataReaderReleased = false;
	const close = () => {
		try { controlSocket?.close?.() } catch (e) { }
		try { dataSocket?.close?.() } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.() } catch (e) { }
	};

	try {
		controlSocket = TCP连接({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(controlWriter, createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
		), 'TURN Allocate request timed out');

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey = null;
		let authAttributes = [];
		const sign = messageToSign => integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& proxy.username !== null
			&& proxy.password !== null
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = textDecoder.decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
			];

			const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
				TURN_STUN_TYPE.ALLOCATE_REQUEST,
				randomTurnTransactionId(),
				[
					createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
					...authAttributes
				]
			), integrityKey);
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			await writeTurnBytes(controlWriter, 拼接字节数据(allocateRequest, ...pipelinedMessages), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			if (pipelinedMessages.length) await writeTurnBytes(controlWriter, 拼接字节数据(...pipelinedMessages), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = TCP连接({ hostname: turnHost, port: proxy.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(dataWriter, await sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { dataReader?.cancel?.() } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock?.() } catch (e) { }
		try { controlReader?.releaseLock?.() } catch (e) { }
		try { dataWriter?.releaseLock?.() } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}
//////////////////////////////////////////////////sstpConnect///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort, TCP连接) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return 数据转Uint8Array(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? 拼接字节数据(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(proxy.hostname);
		const serverPort = proxy.port;
		socket = TCP连接({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(拼接字节数据(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		/** @type {string | null} */
		let targetIp = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await DoH查询(target, 'A');
			const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = 数据转Uint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					if (!streamController) throw new Error('SSTP readable stream is not ready');
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : 拼接字节数据(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						const controller = streamController;
						if (controller) {
							try { controller.close() } catch (e) { }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = streamController;
				if (controller) {
					try { controller.error(error) } catch (e) { }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = 数据转Uint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(拼接字节数据(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
//////////////////////////////////////////////////功能性函数///////////////////////////////////////////////
/**
 * 带秘钥的 Base64 编码
 * @param {string} plaintext - 原始明文字符串
 * @param {string} secret - 秘钥字符串（如 "KEY123"）
 * @returns {string} 经过秘钥处理的 Base64 字符串
 */
function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// 将 Uint8Array 转换为可被 btoa 处理的字符串
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * 带秘钥的 Base64 解码
 * @param {string} encoded - 经秘钥处理过的 Base64 字符串
 * @param {string} secret - 秘钥字符串（必须与编码时相同）
 * @returns {string} 解码后的原始明文字符串
 */
function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function 获取传输协议配置(配置 = {}) {
	const 是gRPC = 配置.传输协议 === 'grpc';
	const [本机标识头, 本机标识键] = 获取本机标识(配置.UUID);
	const 叉混淆JSON = {
		"xPaddingObfsMode": true,
		"xPaddingMethod": "tokenish",
		"xPaddingPlacement": "queryInHeader",
		"xPaddingHeader": 本机标识头,
		"xPaddingKey": 本机标识键
	};
	return {
		type: 是gRPC ? (配置.gRPC模式 === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (配置.传输协议 === 'xhttp' ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(叉混淆JSON))}` : 'ws'),
		路径字段名: 是gRPC ? 'serviceName' : 'path',
		域名字段名: 是gRPC ? 'authority' : 'host'
	};
}

function 获取传输路径参数值(配置 = {}, 节点路径 = '/', 作为优选订阅生成器 = false) {
	const 路径值 = 作为优选订阅生成器 ? '/' : (配置.随机路径 ? 随机路径(节点路径) : 节点路径);
	if (配置.传输协议 !== 'grpc') return 路径值;
	return 路径值.split('?')[0] || '/';
}

function log(...args) {
	if (调试日志打印) console.log(...args);
}

function Clash订阅配置文件热补丁(Clash_原始订阅内容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECH启用 = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const 需要处理ECH = Boolean(uuid && ECH启用);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const 需要处理gRPC = config_JSON?.传输协议 === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_原始订阅内容.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const 添加InlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const 匹配到gRPC网络 = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const 获取代理类型 = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
	const 获取凭据值 = (nodeText, isFlowStyle) => {
		const credentialField = 获取代理类型(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const 插入NameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const 添加Flow格式gRPCUserAgent = (nodeText) => {
		if (!匹配到gRPC网络(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return 添加InlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const 添加Block格式gRPCUserAgent = (nodeLines, topLevelIndent) => {
		const 顶级缩进 = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${顶级缩进}grpc-opts:`, `${顶级缩进}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = 添加InlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let 子级缩进 = topLevelIndent + 2;
		let 已有gRPCUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && 子级缩进 === topLevelIndent + 2) 子级缩进 = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				已有gRPCUserAgent = true;
				break;
			}
		}
		if (!已有gRPCUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(子级缩进)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const 添加Block格式ECHOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (ECH启用 && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join('\n');
		clash_yaml = 插入NameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!需要处理ECH && !需要处理gRPC) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (需要处理gRPC) fullNode = 添加Flow格式gRPCUserAgent(fullNode);
			if (需要处理ECH && 获取凭据值(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (需要处理gRPC && 匹配到gRPC网络(nodeText)) {
				nodeLines = 添加Block格式gRPCUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (需要处理ECH && 获取凭据值(nodeText, false) === uuid.trim()) nodeLines = 添加Block格式ECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function Singbox订阅配置文件热补丁(SingBox_原始订阅内容, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECH启用 = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || "cloudflare-ech.com";
	const sb_json_text = SingBox_原始订阅内容.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		const config = JSON.parse(sb_json_text);
		const 数组化 = value => value === undefined || value === null ? [] : (Array.isArray(value) ? value : [value]);
		const 确保Route = () => config.route = config.route && typeof config.route === 'object' ? config.route : {};
		const 获取DNS规则服务器 = rule => rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string' ? rule.server : null;
		const 添加规则集 = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = 确保Route(), tag = `${type}-${code}`, ruleSet = Array.isArray(route.rule_set) ? route.rule_set : 数组化(route.rule_set);
			if (!ruleSet.some(item => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({ tag, type: 'remote', format: 'binary', url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`, ...(legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}) });
				config.experimental = config.experimental && typeof config.experimental === 'object' ? config.experimental : {};
				config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === 'object' ? config.experimental.cache_file : {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const 迁移规则集字段 = rule => {
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(迁移规则集字段);
				return rule;
			}
			const tags = [];
			for (const geoip of 数组化(rule.geoip)) {
				if (typeof geoip !== 'string') continue;
				if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
				else tags.push(添加规则集('geoip', geoip));
			}
			for (const sourceGeoip of 数组化(rule.source_geoip)) {
				if (typeof sourceGeoip !== 'string') continue;
				tags.push(添加规则集('geoip', sourceGeoip));
				rule.rule_set_ip_cidr_match_source = true;
			}
			for (const geosite of 数组化(rule.geosite)) if (typeof geosite === 'string') tags.push(添加规则集('geosite', geosite));
			if (tags.length) rule.rule_set = [...new Set([...数组化(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const 迁移DNS规则 = (rule, rcodeServerMap) => {
			rule = 迁移规则集字段(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(childRule => 迁移DNS规则(childRule, rcodeServerMap));
				return rule;
			}
			const serverTag = 获取DNS规则服务器(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of ['server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) delete rule[key];
				rule.action = 'predefined';
				rule.rcode = rcodeServerMap.get(serverTag);
			} else if (serverTag && !rule.action) rule.action = 'route';
			return rule;
		};

		if (Array.isArray(config.inbounds)) {
			for (const inbound of config.inbounds) {
				if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
				for (const migration of [
					{ targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
					{ targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
					{ targetKey: 'route_exclude_address', sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'] }
				]) {
					const values = 数组化(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys) values.push(...数组化(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy) addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
					if (inbound.sniff) {
						const sniffRule = { inbound: inbound.tag, action: 'sniff' };
						if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
						addedRules.push(sniffRule);
					}
					if (addedRules.length) {
						const route = 确保Route();
						route.rules = [...addedRules, ...数组化(route.rules)];
					}
				}
				delete inbound.sniff;
				delete inbound.sniff_timeout;
				delete inbound.domain_strategy;
			}
		}

		if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
			const 修补路由规则 = rule => {
				rule = 迁移规则集字段(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules)) rule.rules = rule.rules.map(修补路由规则);
				else if (rule && typeof rule === 'object' && !Array.isArray(rule) && rule.outbound && !rule.action) rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(修补路由规则);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNS地址协议类型 = { 'tcp:': 'tcp', 'udp:': 'udp', 'tls:': 'tls', 'quic:': 'quic', 'https:': 'https', 'h3:': 'h3' };
			const RCode映射 = { success: 'NOERROR', format_error: 'FORMERR', server_failure: 'SERVFAIL', name_error: 'NXDOMAIN', not_implemented: 'NOTIMP', refused: 'REFUSED' };
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null, parsedRCode = '', rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						}
						else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress = dhcpInterface && dhcpInterface.toLowerCase() !== 'auto' ? { type: 'dhcp', interface: dhcpInterface } : { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type = DNS地址协议类型[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer = addressURL.hostname?.startsWith('[') && addressURL.hostname.endsWith(']') ? addressURL.hostname.slice(1, -1) : addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port ? { server_port: Number(addressURL.port) } : {}),
										...((type === 'https' || type === 'h3') && addressURL.pathname && addressURL.pathname !== '/dns-query' ? { path: addressURL.pathname } : {})
									};
								}
							} catch (_) { }
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCode映射[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`, rcode);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (server.address_resolver !== undefined && server.domain_resolver === undefined) server.domain_resolver = server.address_resolver;
					if (server.address_strategy !== undefined && server.domain_strategy === undefined) server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined) server[key] = legacyFakeIP[key];
							}
						}
					}
					migratedServers.push(server);
				}
				dns.servers = migratedServers;
			}

			if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
				const fakeIPServer = { type: 'fakeip', tag: 'fakeip' };
				for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
					const serverTag = 获取DNS规则服务器(rule);
					if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
						fakeIPServer.tag = serverTag;
						break;
					}
				}
				for (const key of ['inet4_range', 'inet6_range']) {
					if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
				}
				if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
				else dns.servers = [fakeIPServer];
			}

			if (Array.isArray(dns.rules)) {
				const migratedRules = [];
				for (const rule of dns.rules) {
					const serverTag = 获取DNS规则服务器(rule);
					const outbound = 数组化(rule?.outbound);
					const DNS路由选项字段 = new Set(['outbound', 'server', 'action', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']);
					const isOutboundAnyDNSRule = rule && typeof rule === 'object' && !Array.isArray(rule) && rule.type !== 'logical'
						&& serverTag && outbound.includes('any') && Object.keys(rule).every(key => DNS路由选项字段.has(key));
					if (isOutboundAnyDNSRule) {
						const route = 确保Route();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of ['strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
						}
						continue;
					}
					migratedRules.push(迁移DNS规则(rule, rcodeServerMap));
				}
				dns.rules = migratedRules;
			}

			delete dns.fakeip;
			delete dns.independent_cache;
		}

		if (config?.route && typeof config.route === 'object') {
			delete config.route.geoip;
			delete config.route.geosite;
		}
		if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

		if (Array.isArray(config.outbounds)) {
			const outboundTags = new Set(config.outbounds.map(outbound => outbound?.tag).filter(Boolean));
			const 引用REJECT = value => value === 'REJECT' || (value && typeof value === 'object' && (Array.isArray(value) ? value.some(引用REJECT) : Object.values(value).some(引用REJECT)));
			if (!outboundTags.has('REJECT') && 引用REJECT({ outbounds: config.outbounds, route: config.route })) config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID 匹配节点的 TLS 热补丁 (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach(outbound => {
				// 仅处理包含 uuid 或 password 且匹配的节点
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// 确保 tls 对象存在
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// 添加/更新 utls 配置
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// 如果提供了 ech_config，添加/更新 ech 配置
					if (ECH启用) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,// 等待 1.13.0+ 版本上线
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("Singbox热补丁执行失败:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function Surge订阅配置文件热补丁(content, url, config_JSON) {
	const 每行内容 = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const 完整节点路径 = config_JSON.随机路径 ? 随机路径(config_JSON.完整节点路径) : config_JSON.完整节点路径;
	let 输出内容 = "";
	for (let x of 每行内容) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const 备改内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}`;
			const 正确内容 = `sni=${host}, skip-cert-verify=${config_JSON.跳过证书验证}, ws=true, ws-path=${完整节点路径.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			输出内容 += x.replace(new RegExp(备改内容, 'g'), 正确内容).replace("[", "").replace("]", "") + '\n';
		} else {
			输出内容 += x + '\n';
		}
	}

	输出内容 = `#!MANAGED-CONFIG ${url} interval=${config_JSON.优选订阅生成.SUBUpdateTime * 60 * 60} strict=false` + 输出内容.substring(输出内容.indexOf('\n'));
	return 输出内容;
}

async function 请求日志记录(env, request, 访问IP, 请求类型 = "Get_SUB", config_JSON, 是否写入KV日志 = true) {
	try {
		const 当前时间 = new Date();
		const 日志内容 = { TYPE: 请求类型, IP: 访问IP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: 当前时间.getTime() };
		if (config_JSON.TG.启用) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const 请求时间 = new Date(日志内容.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
					const 请求URL = new URL(日志内容.URL);
					const msg = `<b>#${config_JSON.优选订阅生成.SUBNAME} 日志通知</b>\n\n` +
						`📌 <b>类型：</b>#${日志内容.TYPE}\n` +
						`🌐 <b>IP：</b><code>${日志内容.IP}</code>\n` +
						`📍 <b>位置：</b>${日志内容.CC}\n` +
						`🏢 <b>ASN：</b>${日志内容.ASN}\n` +
						`🔗 <b>域名：</b><code>${请求URL.host}</code>\n` +
						`🔍 <b>路径：</b><code>${请求URL.pathname + 请求URL.search}</code>\n` +
						`🤖 <b>UA：</b><code>${日志内容.UA}</code>\n` +
						`📅 <b>时间：</b>${请求时间}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>请求用量：</b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							'Accept': 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': 日志内容.UA || 'Unknown',
						}
					});
				}
			} catch (error) { console.error(`读取tg.json出错: ${error.message}`) }
		}
		是否写入KV日志 = ['1', 'true'].includes(env.OFF_LOG) ? false : 是否写入KV日志;
		if (!是否写入KV日志) return;
		let 日志数组 = [];
		const 现有日志 = await env.KV.get('log.json'), KV容量限制 = 4;//MB
		if (现有日志) {
			try {
				日志数组 = JSON.parse(现有日志);
				if (!Array.isArray(日志数组)) { 日志数组 = [日志内容] }
				else if (请求类型 !== "Get_SUB") {
					const 三十分钟前时间戳 = 当前时间.getTime() - 30 * 60 * 1000;
					if (日志数组.some(log => log.TYPE !== "Get_SUB" && log.IP === 访问IP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= 三十分钟前时间戳)) return;
					日志数组.push(日志内容);
					while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
				} else {
					日志数组.push(日志内容);
					while (JSON.stringify(日志数组, null, 2).length > KV容量限制 * 1024 * 1024 && 日志数组.length > 0) 日志数组.shift();
				}
			} catch (e) { 日志数组 = [日志内容] }
		} else { 日志数组 = [日志内容] }
		await env.KV.put('log.json', JSON.stringify(日志数组, null, 2));
	} catch (error) { console.error(`日志记录失败: ${error.message}`) }
}

function 掩码敏感信息(文本, 前缀长度 = 3, 后缀长度 = 2) {
	if (!文本 || typeof 文本 !== 'string') return 文本;
	if (文本.length <= 前缀长度 + 后缀长度) return 文本; // 如果长度太短，直接返回

	const 前缀 = 文本.slice(0, 前缀长度);
	const 后缀 = 文本.slice(-后缀长度);
	const 星号数量 = 文本.length - 前缀长度 - 后缀长度;

	return `${前缀}${'*'.repeat(星号数量)}${后缀}`;
}

async function MD5MD5(文本) {
	const 编码器 = new TextEncoder();

	const 第一次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(文本));
	const 第一次哈希数组 = Array.from(new Uint8Array(第一次哈希));
	const 第一次十六进制 = 第一次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

	const 第二次哈希 = await crypto.subtle.digest('MD5', 编码器.encode(第一次十六进制.slice(7, 27)));
	const 第二次哈希数组 = Array.from(new Uint8Array(第二次哈希));
	const 第二次十六进制 = 第二次哈希数组.map(字节 => 字节.toString(16).padStart(2, '0')).join('');

	return 第二次十六进制.toLowerCase();
}

function 随机路径(完整节点路径 = "/") {
	const 常用路径目录 = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const 随机数 = Math.floor(Math.random() * 3 + 1);
	const 随机路径 = 常用路径目录.sort(() => 0.5 - Math.random()).slice(0, 随机数).join('/');
	if (完整节点路径 === "/") return `/${随机路径}`;
	else return `/${随机路径 + 完整节点路径.replace('/?', '?')}`;
}

function 替换星号为随机字符(内容) {
	if (typeof 内容 !== 'string' || !内容.includes('*')) return 内容;
	const 字符集 = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return 内容.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += 字符集[Math.floor(Math.random() * 字符集.length)];
		return s;
	});
}

const DoH缓存 = {};
const DoH缓存最大条目 = 256;
const DoH记录类型映射 = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function DoH查询(域名, 记录类型, DoH解析服务 = "https://cloudflare-dns.com/dns-query") {
	const 规范化域名 = String(域名 || '').trim().toLowerCase().replace(/\.$/, '');
	const 规范化记录类型 = String(记录类型 || '').trim().toUpperCase();
	const 缓存键 = `${规范化域名}:${规范化记录类型}`;
	const qtype = DoH记录类型映射[规范化记录类型] || 1;
	const 当前时间戳 = Date.now();
	const 现缓存项 = DoH缓存[缓存键];
	if (现缓存项 && 当前时间戳 < 现缓存项.过期时间) {
		log(`[DoH查询] 命中缓存 ${域名} ${记录类型} via ${DoH解析服务}`);
		return 现缓存项.data.map(data => ({ type: qtype, data }));
	}
	const 开始时间 = performance.now();
	log(`[DoH查询] 开始查询 ${域名} ${记录类型} via ${DoH解析服务}`);
	try {
		// 记录类型字符串转数值
		// 编码域名为 DNS wire format labels
		const 编码域名 = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// 构建 DNS 查询报文
		const qname = 编码域名(规范化域名);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (递归查询)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// 通过 POST 发送 dns-message 请求
		log(`[DoH查询] 发送查询报文 ${域名} via ${DoH解析服务} (type=${qtype}, ${query.length}字节)`);
		const response = await fetch(DoH解析服务, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoH查询] 请求失败 ${域名} ${记录类型} via ${DoH解析服务} 响应代码:${response.status}`);
			return [];
		}

		// 解析 DNS 响应报文
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[DoH查询] 收到响应 ${域名} ${记录类型} via ${DoH解析服务} (${buf.length}字节, ${ancount}条应答)`);

		// 解析域名（处理指针压缩）
		const 解析域名 = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// 跳过 Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = 解析域名(offset);
			offset = /** @type {number} */ (end) + 4; // +4 跳过 QTYPE + QCLASS
		}

		// 解析 Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = 解析域名(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A 记录
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA 记录
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT 记录 (长度前缀字符串)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME 记录
				const [cname] = 解析域名(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		log(`[DoH查询] 查询完成 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms 共${answers.length}条结果${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		// DoH 缓存至少保留 5 分钟，响应 TTL 更长时尊重响应 TTL；空响应使用 5 分钟负缓存
		const 相关记录 = answers.filter(answer => answer.type === qtype);
		const 最小TTL = 相关记录.length > 0 ? Math.min(...相关记录.map(a => a.TTL)) : 0;
		const 缓存TTL = Math.max(最小TTL, 5 * 60);
		const 缓存过期时间 = Date.now() + 缓存TTL * 1000;
		const 缓存数据 = 相关记录.map(answer => answer.data);
		if (缓存数据.length > 0 || answers.length === 0) {
			if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
				const 清理时间戳 = Date.now();
				for (const [缓存条目键, 缓存条目] of Object.entries(DoH缓存)) {
					if (清理时间戳 >= 缓存条目.过期时间) delete DoH缓存[缓存条目键];
				}
				if (Object.keys(DoH缓存).length >= DoH缓存最大条目) {
					delete DoH缓存[Object.keys(DoH缓存)[0]];
				}
			}
			DoH缓存[缓存键] = { data: 缓存数据, 过期时间: 缓存过期时间 };
			log(`[DoH查询] 写入缓存 ${域名} ${记录类型} TTL=${缓存TTL}s${缓存数据.length === 0 ? '（空结果）' : ''}`);
		}
		return answers;
	} catch (error) {
		const 耗时 = (performance.now() - 开始时间).toFixed(2);
		console.error(`[DoH查询] 查询失败 ${域名} ${记录类型} via ${DoH解析服务} ${耗时}ms:`, error);
		return [];
	}
}

async function 读取config_JSON(env, hostname, userID, UA = "Mozilla/5.0", 重置配置 = false) {
	const _p = 特征码字典[0];
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", 占位符 = '{{IP:PORT}}', 初始化开始时间 = performance.now(), 默认配置JSON = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		ALPN: "",
		协议类型: "v" + "le" + "ss",
		传输协议: "ws",
		gRPC模式: "gun",
		gRPCUserAgent: UA,
		跳过证书验证: false,
		启用0RTT: false,
		TLS分片: null,
		随机路径: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			加密方式: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		优选订阅生成: {
			local: true, // true: 基于本地的优选地址  false: 优选订阅生成器
			本地IP库: {
				随机IP: true, // 当 随机IP 为true时生效，启用随机IP的数量，否则使用KV内的ADD.txt
				随机数量: 16,
				指定端口: -1,
			},
			SUB: null,
			SUBNAME: "edge" + "tunnel",
			SUBUpdateTime: 3, // 订阅更新时间（小时）
			TOKEN: await MD5MD5(hostname + userID),
		},
		订阅转换配置: {
			SUBAPI: `https://SUBAPI.${特征码字典[1]}ssss.net`,
			SUBCONFIG: `https://raw.githubusercontent.com/${特征码字典[1]}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
			SUBEMOJI: false,
			SUBLIST: false, //仅输出节点信息
			UDP: false, // 启用 UDP
			XUDP: false, // 启用 XUDP
			TLS13: false, // 启用 TLS 1.3
			APPEND_TYPE: false, // 插入节点类型
			SORT: false, // 基础节点排序
			EXPAND: true, // 展开规则全文
		},
		反代: {
			[_p]: "auto",
			SOCKS5: {
				启用: null,
				全局: false,
				账号: '',
				白名单: SOCKS5白名单,
			},
			路径模板: {
				[_p]: "proxyip=" + 占位符,
				SOCKS5: {
					全局: "socks5://" + 占位符,
					标准: "socks5=" + 占位符
				},
				HTTP: {
					全局: "http://" + 占位符,
					标准: "http=" + 占位符
				},
				HTTPS: {
					全局: "https://" + 占位符,
					标准: "https=" + 占位符
				},
				TURN: {
					全局: "turn://" + 占位符,
					标准: "turn=" + 占位符
				},
				SSTP: {
					全局: "sstp://" + 占位符,
					标准: "sstp=" + 占位符
				},
			},
		},
		TG: {
			启用: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || 重置配置 == true) {
			await env.KV.put('config.json', JSON.stringify(默认配置JSON, null, 2));
			config_JSON = 默认配置JSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`读取config_JSON出错: ${error.message}`);
		config_JSON = 默认配置JSON;
	}

	if (!config_JSON.订阅转换配置.SUBLIST) config_JSON.订阅转换配置.SUBLIST = false;
	if (!config_JSON.订阅转换配置.UDP) config_JSON.订阅转换配置.UDP = false;
	if (!config_JSON.订阅转换配置.XUDP) config_JSON.订阅转换配置.XUDP = false;
	if (!config_JSON.订阅转换配置.TLS13) config_JSON.订阅转换配置.TLS13 = false;
	if (!config_JSON.订阅转换配置.APPEND_TYPE) config_JSON.订阅转换配置.APPEND_TYPE = false;
	if (!config_JSON.订阅转换配置.SORT) config_JSON.订阅转换配置.SORT = false;
	if (typeof config_JSON.订阅转换配置.EXPAND !== 'boolean') config_JSON.订阅转换配置.EXPAND = true;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.随机路径) config_JSON.随机路径 = false;
	if (!config_JSON.启用0RTT) config_JSON.启用0RTT = false;

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';
	if (!config_JSON.ALPN) config_JSON.ALPN = "";

	if (!config_JSON.gRPC模式) config_JSON.gRPC模式 = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { 加密方式: "aes-128-gcm", TLS: false };

	if (!config_JSON.反代.路径模板?.[_p]) {
		config_JSON.反代.路径模板 = {
			[_p]: "proxyip=" + 占位符,
			SOCKS5: {
				全局: "socks5://" + 占位符,
				标准: "socks5=" + 占位符
			},
			HTTP: {
				全局: "http://" + 占位符,
				标准: "http=" + 占位符
			},
			HTTPS: {
				全局: "https://" + 占位符,
				标准: "https=" + 占位符
			},
			TURN: {
				全局: "turn://" + 占位符,
				标准: "turn=" + 占位符
			},
			SSTP: {
				全局: "sstp://" + 占位符,
				标准: "sstp=" + 占位符
			},
		};
	}
	if (!config_JSON.反代.路径模板.HTTPS) config_JSON.反代.路径模板.HTTPS = { 全局: "https://" + 占位符, 标准: "https=" + 占位符 };
	if (!config_JSON.反代.路径模板.TURN) config_JSON.反代.路径模板.TURN = { 全局: "turn://" + 占位符, 标准: "turn=" + 占位符 };
	if (!config_JSON.反代.路径模板.SSTP) config_JSON.反代.路径模板.SSTP = { 全局: "sstp://" + 占位符, 标准: "sstp=" + 占位符 };

	const 代理配置 = config_JSON.反代.路径模板[config_JSON.反代.SOCKS5.启用?.toUpperCase()];

	let 路径反代参数 = '';
	if (代理配置 && config_JSON.反代.SOCKS5.账号) 路径反代参数 = (config_JSON.反代.SOCKS5.全局 ? 代理配置.全局 : 代理配置.标准).replace(占位符, config_JSON.反代.SOCKS5.账号);
	else if (config_JSON.反代[_p] !== 'auto') 路径反代参数 = config_JSON.反代.路径模板[_p].replace(占位符, config_JSON.反代[_p]);

	let 反代查询参数 = '';
	if (路径反代参数.includes('?')) {
		const [反代路径部分, 反代查询部分] = 路径反代参数.split('?');
		路径反代参数 = 反代路径部分;
		反代查询参数 = 反代查询部分;
	}

	config_JSON.PATH = config_JSON.PATH.replace(路径反代参数, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [路径部分, ...查询数组] = normalizedPath.split('?');
	const 查询部分 = 查询数组.length ? '?' + 查询数组.join('?') : '';
	const 最终查询部分 = 反代查询参数 ? (查询部分 ? 查询部分 + '&' + 反代查询参数 : '?' + 反代查询参数) : 查询部分;
	config_JSON.完整节点路径 = (路径部分 || '/') + (路径部分 && 路径反代参数 ? '/' : '') + 路径反代参数 + 最终查询部分 + (config_JSON.启用0RTT ? (最终查询部分 ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLS分片 && config_JSON.TLS分片 !== null) config_JSON.TLS分片 = null;
	const TLS分片参数 = config_JSON.TLS分片 == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLS分片 == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINK参数 = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: 传输协议, 路径字段名, 域名字段名 } = 获取传输协议配置(config_JSON);
	const 传输路径参数值 = 获取传输路径参数值(config_JSON, config_JSON.完整节点路径);
	config_JSON.LINK = config_JSON.协议类型 === 'ss'
		? `${config_JSON.协议类型}://${btoa(config_JSON.SS.加密方式 + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.完整节点路径.includes('?') ? config_JSON.完整节点路径.replace('?', '?enc=' + config_JSON.SS.加密方式 + '&') : (config_JSON.完整节点路径 + '?enc=' + config_JSON.SS.加密方式)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + ECHLINK参数}#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`
		: `${config_JSON.协议类型}://${userID}@${host}:443?security=tls&type=${传输协议 + ECHLINK参数}&${域名字段名}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${路径字段名}=${encodeURIComponent(传输路径参数值) + TLS分片参数}&encryption=none#${encodeURIComponent(config_JSON.优选订阅生成.SUBNAME)}`;
	config_JSON.优选订阅生成.TOKEN = await MD5MD5(hostname + userID);

	const 初始化TG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = { 启用: config_JSON.TG.启用 ? config_JSON.TG.启用 : false, ...初始化TG_JSON };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(初始化TG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? 掩码敏感信息(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`读取tg.json出错: ${error.message}`);
	}

	const 初始化CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...初始化CF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(初始化CF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`请求 CF_JSON.UsageAPI 失败: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? 掩码敏感信息(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? 掩码敏感信息(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? 掩码敏感信息(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`读取cf.json出错: ${error.message}`);
	}

	config_JSON.加载时间 = (performance.now() - 初始化开始时间).toFixed(2) + 'ms';
	return config_JSON;
}

function 识别运营商(request) {
	const cf = request?.cf;
	const ASN运营商映射 = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const 运营商关键词映射 = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const 组织名称 = String(cf?.asOrganization || '').toLowerCase();
	const 命中运营商 = 运营商关键词映射.find(({ pattern }) => pattern.test(组织名称))?.code;
	return 命中运营商 || ASN运营商映射[String(cf?.asn || '')] || 'cf';
}

async function 生成随机IP(request, count = 16, 指定端口 = -1) {
	const url = new URL(request.url);
	const 查询参数运营商 = String(url.searchParams.get('cnIspCode') || '').toLowerCase();
	const 运营商文件标识 = ['ct', 'cu', 'cmcc', 'cf'].includes(查询参数运营商) ? 查询参数运营商 : 识别运营商(request);
	const 运营商名称映射 = {
		cmcc: 'CF移动优选',
		cu: 'CF联通优选',
		ct: 'CF电信优选',
		cf: 'CF官方优选',
	};
	const cidr_url = 运营商文件标识 === 'cf' ? `https://raw.githubusercontent.com/${特征码字典[1]}/${特征码字典[1]}/main/CF-CIDR.txt` : `https://raw.githubusercontent.com/${特征码字典[1]}/${特征码字典[1]}/main/CF-CIDR/${运营商文件标识}.txt`;
	const cfname = 运营商名称映射[运营商文件标识] || 'CF官方优选';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	try { const res = await fetch(cidr_url); cidrList = res.ok ? await 整理成数组(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const 目标端口 = 指定端口 === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: 指定端口;
		return `${ip}:${目标端口}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function 整理成数组(内容) {
	var 替换后的内容 = 内容.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (替换后的内容.charAt(0) == ',') 替换后的内容 = 替换后的内容.slice(1);
	if (替换后的内容.charAt(替换后的内容.length - 1) == ',') 替换后的内容 = 替换后的内容.slice(0, 替换后的内容.length - 1);
	const 地址数组 = 替换后的内容.split(',');
	return 地址数组;
}

async function 获取优选订阅生成器数据(优选订阅生成器HOST, uid = "000000") {
	let 优选IP = [], 其他节点LINK = '', 格式化HOST = 优选订阅生成器HOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(格式化HOST)) 格式化HOST = `https://${格式化HOST}`;

	try {
		const url = new URL(格式化HOST);
		格式化HOST = url.origin;
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器格式化异常:${error.message}`);
		return [优选IP, 其他节点LINK];
	}

	const 优选订阅生成器URL = `${格式化HOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(优选订阅生成器URL, {
			headers: { 'User-Agent': 汇聚订阅_UA + ' Uid/0x' + uid + ' Version/' + EDT_版本号 }
		});

		if (!response.ok) {
			优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${response.statusText}`);
			return [优选IP, 其他节点LINK];
		}

		const 优选订阅生成器返回订阅内容 = atob(await response.text());
		const 订阅行列表 = 优选订阅生成器返回订阅内容.includes('\r\n')
			? 优选订阅生成器返回订阅内容.split('\r\n')
			: 优选订阅生成器返回订阅内容.split('\n');

		for (const 行内容 of 订阅行列表) {
			if (!行内容.trim()) continue; // 跳过空行
			if (行内容.includes('00000000-0000-4000-8000-000000000000') && 行内容.includes('example.com')) {
				// 这是优选IP行，提取 域名:端口#备注
				const 地址匹配 = 行内容.match(/:\/\/[^@]+@([^?]+)/);
				if (地址匹配) {
					let 地址端口 = 地址匹配[1], 备注 = ''; // 域名:端口 或 IP:端口
					const 备注匹配 = 行内容.match(/#(.+)$/);
					if (备注匹配) 备注 = '#' + decodeURIComponent(备注匹配[1]);
					优选IP.push(地址端口 + 备注);
				}
			} else {
				其他节点LINK += 行内容 + '\n';
			}
		}
	} catch (error) {
		优选IP.push(`127.0.0.1:1234#${优选订阅生成器HOST}优选订阅生成器异常:${error.message}`);
	}

	return [优选IP, 其他节点LINK];
}

async function 请求优选API(urls, 默认端口 = '443', uid = "000000", 超时时间 = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), 反代IP池 = new Set();
	let 订阅链接响应的明文LINK内容 = '', 需要订阅转换订阅URLs = [];
	await Promise.allSettled(urls.map(async (url) => {
		// 检查URL是否包含备注名
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const API备注名 = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const 优选IP作为反代IP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [优选IP, 其他节点LINK] = await 获取优选订阅生成器数据(urlWithoutHash, uid);
				// 处理第一个数组 - 优选IP
				if (API备注名) {
					for (const ip of 优选IP) {
						const 处理后IP = ip.includes('#')
							? `${ip} [${API备注名}]`
							: `${ip}#[${API备注名}]`;
						results.add(处理后IP);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of 优选IP) {
						results.add(ip);
						if (优选IP作为反代IP) 反代IP池.add(ip.split('#')[0]);
					}
				}
				// 处理第二个数组 - 其他节点LINK
				if (其他节点LINK && typeof 其他节点LINK === 'string' && API备注名) {
					const 处理后LINK内容 = 其他节点LINK.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整链接 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API备注名}]`)}`
							: `${link}${encodeURIComponent(`#[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容;
				} else if (其他节点LINK && typeof 其他节点LINK === 'string') {
					订阅链接响应的明文LINK内容 += 其他节点LINK;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), 超时时间);
			const response = await fetch(urlWithoutHash, { signal: controller.signal, headers: { 'User-Agent': 汇聚订阅_UA + ' Uid/0x' + uid + ' Version/' + EDT_版本号 } });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// 根据 Content-Type 响应头判断编码优先级
				let decoders = ['utf-8', 'gb2312']; // 默认优先 UTF-8
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // 如果明确指定 GB 系编码，优先尝试 GB2312
				}

				// 尝试多种编码解码
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// 验证解码结果的有效性
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// 如果有替换字符 (U+FFFD)，说明编码不匹配，继续尝试下一个编码
							continue;
						}
					} catch (e) {
						// 该编码解码失败，尝试下一个
						continue;
					}
				}

				// 如果所有编码都失败或无效，尝试 response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// 如果返回的是空或无效数据，返回
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// 预处理订阅内容
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox 配置
				需要订阅转换订阅URLs.add(url);
				return;
			}
			*/

			let 预处理订阅明文内容 = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					预处理订阅明文内容 = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (预处理订阅明文内容.split('#')[0].includes('://')) {
				// 处理LINK内容
				if (API备注名) {
					const 处理后LINK内容 = 预处理订阅明文内容.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const 完整链接 = link.includes('#')
							? `${link}${encodeURIComponent(` [${API备注名}]`)}`
							: `${link}${encodeURIComponent(`#[${API备注名}]`)}`;
						return `${完整链接}${lineEnd}`;
					});
					订阅链接响应的明文LINK内容 += 处理后LINK内容 + '\n';
				} else {
					订阅链接响应的明文LINK内容 += 预处理订阅明文内容 + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// 处理第一个数组 - 优选IP
					if (API备注名) {
						const 处理后IP = ipItem.includes('#')
							? `${ipItem} [${API备注名}]`
							: `${ipItem}#[${API备注名}]`;
						results.add(处理后IP);
					} else {
						results.add(ipItem);
					}
					if (优选IP作为反代IP) 反代IP池.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IP地址') && headers.includes('端口') && headers.includes('数据中心')) {
					const ipIdx = headers.indexOf('IP地址'), portIdx = headers.indexOf('端口');
					const remarkIdx = headers.indexOf('国家') > -1 ? headers.indexOf('国家') :
						headers.indexOf('城市') > -1 ? headers.indexOf('城市') : headers.indexOf('数据中心');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// 处理第一个数组 - 优选IP
						if (API备注名) {
							const 处理后IP = `${ipItem} [${API备注名}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('延迟')) && headers.some(h => h.includes('下载速度'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('延迟'));
					const speedIdx = headers.findIndex(h => h.includes('下载速度'));
					const port = parsedUrl.searchParams.get('port') || 默认端口;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CF优选 ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// 处理第一个数组 - 优选IP
						if (API备注名) {
							const 处理后IP = `${ipItem} [${API备注名}]`;
							results.add(处理后IP);
						} else {
							results.add(ipItem);
						}
						if (优选IP作为反代IP) 反代IP池.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// 将LINK内容转换为数组并去重
	const LINK数组 = 订阅链接响应的明文LINK内容.trim() ? [...new Set(订阅链接响应的明文LINK内容.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINK数组, 需要订阅转换订阅URLs, Array.from(反代IP池)];
}

async function 反代参数获取(url, uuid, 默认反代IP = '', 默认反代兜底 = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let 反代IP = 默认反代IP, 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {}, 启用反代兜底 = 默认反代兜底;
	const 反代上下文 = { 木马反代地址: null, 反代IP, 代理类型: null, 代理账号: '', 代理全局: false, 代理参数: {}, 反代兜底: 启用反代兜底 };
	const 保存快照 = () => {
		反代上下文.反代IP = 反代IP;
		反代上下文.代理类型 = 启用SOCKS5反代;
		反代上下文.代理账号 = 我的SOCKS5账号;
		反代上下文.代理全局 = 启用SOCKS5全局反代;
		反代上下文.代理参数 = { ...parsedSocks5Address };
		反代上下文.反代兜底 = 启用反代兜底;
	};

	const 链式代理路径匹配 = pathname.match(/\/video\/(.+)$/i);
	if (链式代理路径匹配) {
		try {
			const 链式代理明文 = base64SecretDecode(链式代理路径匹配[1].replace(/\/+$/, ''), uuid);
			const { type, ...链式代理地址 } = JSON.parse(链式代理明文);
			if (!type || !反代协议默认端口[String(type).toLowerCase()]) throw new Error('链式代理类型无效');
			if (!链式代理地址.hostname || !链式代理地址.port) throw new Error('链式代理地址缺少 hostname 或 port');
			我的SOCKS5账号 = '';
			反代IP = '链式代理';
			启用反代兜底 = false;
			启用SOCKS5全局反代 = true;
			启用SOCKS5反代 = String(type).toLowerCase();
			parsedSocks5Address = {
				username: 链式代理地址.username,
				password: 链式代理地址.password,
				hostname: 链式代理地址.hostname,
				port: Number(链式代理地址.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('链式代理端口无效');
			保存快照();
			return 反代上下文;
		} catch (err) {
			console.error('解析链式代理参数失败:', err.message);
		}
	}

	我的SOCKS5账号 = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	启用SOCKS5全局反代 = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) 启用SOCKS5反代 = 'socks5';
	else if (searchParams.get('http')) 启用SOCKS5反代 = 'http';
	else if (searchParams.get('https')) 启用SOCKS5反代 = 'https';
	else if (searchParams.get('turn')) 启用SOCKS5反代 = 'turn';
	else if (searchParams.get('sstp')) 启用SOCKS5反代 = 'sstp';

	const 解析代理URL = (值, 强制全局 = true) => {
		const 匹配 = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(值 || '');
		if (!匹配) return false;
		启用SOCKS5反代 = 匹配[1].toLowerCase();
		我的SOCKS5账号 = 匹配[2].split('/')[0];
		if (强制全局) 启用SOCKS5全局反代 = true;
		return true;
	};

	const 设置反代IP = (值) => {
		反代IP = 值;
		启用SOCKS5反代 = null;
		启用反代兜底 = false;
	};

	const 提取路径值 = (值) => {
		if (!值.includes('://')) {
			const 斜杠索引 = 值.indexOf('/');
			return 斜杠索引 > 0 ? 值.slice(0, 斜杠索引) : 值;
		}
		const 协议拆分 = 值.split('://');
		if (协议拆分.length !== 2) return 值;
		const 斜杠索引 = 协议拆分[1].indexOf('/');
		return 斜杠索引 > 0 ? `${协议拆分[0]}://${协议拆分[1].slice(0, 斜杠索引)}` : 值;
	};

	const 木马路径匹配 = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (木马路径匹配) {
		try {
			反代上下文.木马反代地址 = 解析木马反代地址(木马路径匹配[1].replace(/\/+$/, ''));
		} catch (err) {
			console.error('解析木马反代地址失败:', err.message);
			反代上下文.木马反代地址 = null;
		}
	}

	const 查询反代IP = searchParams.get('proxyip');
	if (查询反代IP !== null) {
		if (!解析代理URL(查询反代IP)) {
			设置反代IP(查询反代IP);
			保存快照();
			return 反代上下文;
		}
	} else {
		let 匹配 = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (匹配) {
			const 类型 = 匹配[1].toLowerCase();
			启用SOCKS5反代 = 类型 === 'sock' || 类型 === 'socks' ? 'socks5' : 类型;
			我的SOCKS5账号 = 匹配[2].split('/')[0];
			启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const 类型 = 匹配[1].toLowerCase();
			我的SOCKS5账号 = 匹配[2].split('/')[0];
			启用SOCKS5反代 = 类型.includes('sstp') ? 'sstp' : (类型.includes('turn') ? 'turn' : (类型.includes('https') ? 'https' : (类型.includes('http') ? 'http' : 'socks5')));
			if (类型.startsWith('g')) 启用SOCKS5全局反代 = true;
		} else if ((匹配 = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const 路径反代值 = 提取路径值(匹配[2]);
			if (!解析代理URL(路径反代值)) {
				设置反代IP(路径反代值);
				保存快照();
				return 反代上下文;
			}
		}
	}

	if (!我的SOCKS5账号) {
		启用SOCKS5反代 = null;
		保存快照();
		return 反代上下文;
	}

	try {
		parsedSocks5Address = await 获取SOCKS5账号(我的SOCKS5账号, 获取代理默认端口(启用SOCKS5反代));
		if (searchParams.get('socks5')) 启用SOCKS5反代 = 'socks5';
		else if (searchParams.get('http')) 启用SOCKS5反代 = 'http';
		else if (searchParams.get('https')) 启用SOCKS5反代 = 'https';
		else if (searchParams.get('turn')) 启用SOCKS5反代 = 'turn';
		else if (searchParams.get('sstp')) 启用SOCKS5反代 = 'sstp';
		else 启用SOCKS5反代 = 启用SOCKS5反代 || 'socks5';
	} catch (err) {
		console.error('解析SOCKS5地址失败:', err.message);
		启用SOCKS5反代 = null;
	}
	保存快照();
	return 反代上下文;
}

const 反代协议默认端口 = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function 获取代理默认端口(类型) {
	return 反代协议默认端口[String(类型 || '').toLowerCase()] || 80;
}

const SOCKS5账号Base64正则 = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPv6方括号正则 = /^\[.*\]$/;
function 获取SOCKS5账号(address, 默认端口 = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5账号Base64正则.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('无效的 SOCKS 地址格式：认证部分必须是 "username:password" 的形式');

	let hostname = hostPart, port = 默认端口;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('无效的 SOCKS 地址格式：端口号必须是数字');
	if (hostname.includes(":") && !IPv6方括号正则.test(hostname)) throw new Error('无效的 SOCKS 地址格式：IPv6 地址必须用方括号括起来，如 [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`账户获取失败: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("未找到账户");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`查询失败: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("未找到账户数据");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(`统计结果 - Pages: ${pages}, Workers: ${workers}, 总计: ${total}, 上限: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('获取使用量错误:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function 解析地址端口(proxyIP, 目标域名 = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function 解析地址端口字符串(str) {
		let 地址 = str, 端口 = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			地址 = parts[0] + ']';
			端口 = parseInt(parts[1], 10) || 端口;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			地址 = str.slice(0, colonIndex);
			端口 = parseInt(str.slice(colonIndex + 1), 10) || 端口;
		}
		return [地址, 端口];
	}

	function 解析TXT反代记录(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => 解析地址端口字符串(prefix));
	}

	const 反代IP数组 = await 整理成数组(proxyIP);
	let 所有反代数组 = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	// 遍历数组中的每个IP元素进行处理
	for (const singleProxyIP of 反代IP数组) {
		let [地址, 端口] = 解析地址端口字符串(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
		}

		// 判断是否是域名（非IP地址）
		if (ipv4Regex.test(地址) || ipv6Regex.test(地址)) {
			log(`[反代解析] ${地址} 为IP地址，直接使用`);
			所有反代数组.push([地址, 端口]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			DoH查询(地址, 'TXT'),
			DoH查询(地址, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = 解析TXT反代记录(txtData);
		if (txtAddresses.length > 0) {
			log(`[反代解析] ${地址} 使用TXT记录，共${txtAddresses.length}个结果`);
			所有反代数组.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			log(`[反代解析] ${地址} 未获取到TXT记录，使用A记录，共${ipv4List.length}个结果`);
			所有反代数组.push(...ipv4List.map(ip => [ip, 端口]));
			continue;
		}

		const aaaaRecords = await DoH查询(地址, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			log(`[反代解析] ${地址} 未获取到TXT和A记录，使用AAAA记录，共${ipv6List.length}个结果`);
			所有反代数组.push(...ipv6List.map(ip => [ip, 端口]));
		} else {
			log(`[反代解析] ${地址} 未获取到TXT、A和AAAA记录，保留原域名`);
			所有反代数组.push([地址, 端口]);
		}
	}
	const 排序后数组 = 所有反代数组.sort((a, b) => a[0].localeCompare(b[0]));
	const 目标根域名 = 目标域名.includes('.') ? 目标域名.split('.').slice(-2).join('.') : 目标域名;
	let 随机种子 = [...(目标根域名 + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	log(`[反代解析] 随机种子: ${随机种子}\n目标站点: ${目标根域名}`)
	const 洗牌后 = [...排序后数组].sort(() => (随机种子 = (随机种子 * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const 解析结果 = 洗牌后.slice(0, 8);
	log(`[反代解析] 解析完成 总数: ${解析结果.length}个\n${解析结果.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return 解析结果;
}

//////////////////////////////////////////////////////HTML伪装页面///////////////////////////////////////////////
async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, 访问IP) {
	const now = new Date();
	const 格式化时间戳 = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const 随机字符串 = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${随机字符串} &bull; ${格式化时间戳} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${随机字符串}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${访问IP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}

/*

Genesis
בראשית
Tanach with Nikkud
http://www.tanach.us/Tanach.xml

בראשית



Chapter 1

בְּרֵאשִׁית בָּרָא אֱלֹהִים אֵת הַשָּׁמַיִם וְאֵת הָאָרֶץ׃
וְהָאָרֶץ הָיְתָה תֹהוּ וָבֹהוּ וְחֹשֶׁךְ עַל־פְּנֵי תְהוֹם וְרוּחַ אֱלֹהִים מְרַחֶפֶת עַל־פְּנֵי הַמָּיִם׃
וַיֹּאמֶר אֱלֹהִים יְהִי אוֹר וַיְהִי־אוֹר׃
וַיַּרְא אֱלֹהִים אֶת־הָאוֹר כִּי־טוֹב וַיַּבְדֵּל אֱלֹהִים בֵּין הָאוֹר וּבֵין הַחֹשֶׁךְ׃
וַיִּקְרָא אֱלֹהִים לָאוֹר יוֹם וְלַחֹשֶׁךְ קָרָא לָיְלָה וַיְהִי־עֶרֶב וַיְהִי־בֹקֶר יוֹם אֶחָד׃
וַיֹּאמֶר אֱלֹהִים יְהִי רָקִיעַ בְּתוֹךְ הַמָּיִם וִיהִי מַבְדִּיל בֵּין מַיִם לָמָיִם׃
וַיַּעַשׂ אֱלֹהִים אֶת־הָרָקִיעַ וַיַּבְדֵּל בֵּין הַמַּיִם אֲשֶׁר מִתַּחַת לָרָקִיעַ וּבֵין הַמַּיִם אֲשֶׁר מֵעַל לָרָקִיעַ וַיְהִי־כֵן׃
וַיִּקְרָא אֱלֹהִים לָרָקִיעַ שָׁמָיִם וַיְהִי־עֶרֶב וַיְהִי־בֹקֶר יוֹם שֵׁנִי׃
וַיֹּאמֶר אֱלֹהִים יִקָּווּ הַמַּיִם מִתַּחַת הַשָּׁמַיִם אֶל־מָקוֹם אֶחָד וְתֵרָאֶה הַיַּבָּשָׁה וַיְהִי־כֵן׃
וַיִּקְרָא אֱלֹהִים לַיַּבָּשָׁה אֶרֶץ וּלְמִקְוֵה הַמַּיִם קָרָא יַמִּים וַיַּרְא אֱלֹהִים כִּי־טוֹב׃
וַיֹּאמֶר אֱלֹהִים תַּדְשֵׁא הָאָרֶץ דֶּשֶׁא עֵשֶׂב מַזְרִיעַ זֶרַע עֵץ פְּרִי עֹשֶׂה פְּרִי לְמִינוֹ אֲשֶׁר זַרְעוֹ־בוֹ עַל־הָאָרֶץ וַיְהִי־כֵן׃
וַתּוֹצֵא הָאָרֶץ דֶּשֶׁא עֵשֶׂב מַזְרִיעַ זֶרַע לְמִינֵהוּ וְעֵץ עֹשֶׂה־פְּרִי אֲשֶׁר זַרְעוֹ־בוֹ לְמִינֵהוּ וַיַּרְא אֱלֹהִים כִּי־טוֹב׃
וַיְהִי־עֶרֶב וַיְהִי־בֹקֶר יוֹם שְׁלִישִׁי׃
וַיֹּאמֶר אֱלֹהִים יְהִי מְאֹרֹת בִּרְקִיעַ הַשָּׁמַיִם לְהַבְדִּיל בֵּין הַיּוֹם וּבֵין הַלָּיְלָה וְהָיוּ לְאֹתֹת וּלְמוֹעֲדִים וּלְיָמִים וְשָׁנִים׃
וְהָיוּ לִמְאוֹרֹת בִּרְקִיעַ הַשָּׁמַיִם לְהָאִיר עַל־הָאָרֶץ וַיְהִי־כֵן׃
וַיַּעַשׂ אֱלֹהִים אֶת־שְׁנֵי הַמְּאֹרֹת הַגְּדֹלִים אֶת־הַמָּאוֹר הַגָּדֹל לְמֶמְשֶׁלֶת הַיּוֹם וְאֶת־הַמָּאוֹר הַקָּטֹן לְמֶמְשֶׁלֶת הַלַּיְלָה וְאֵת הַכּוֹכָבִים׃
וַיִּתֵּן אֹתָם אֱלֹהִים בִּרְקִיעַ הַשָּׁמָיִם לְהָאִיר עַל־הָאָרֶץ׃
וְלִמְשֹׁל בַּיּוֹם וּבַלַּיְלָה וּלֲהַבְדִּיל בֵּין הָאוֹר וּבֵין הַחֹשֶׁךְ וַיַּרְא אֱלֹהִים כִּי־טוֹב׃
וַיְהִי־עֶרֶב וַיְהִי־בֹקֶר יוֹם רְבִיעִי׃
וַיֹּאמֶר אֱלֹהִים יִשְׁרְצוּ הַמַּיִם שֶׁרֶץ נֶפֶשׁ חַיָּה וְעוֹף יְעוֹפֵף עַל־הָאָרֶץ עַל־פְּנֵי רְקִיעַ הַשָּׁמָיִם׃
וַיִּבְרָא אֱלֹהִים אֶת־הַתַּנִּינִם הַגְּדֹלִים וְאֵת כָּל־נֶפֶשׁ הַחַיָּה הָרֹמֶשֶׂת אֲשֶׁר שָׁרְצוּ הַמַּיִם לְמִינֵהֶם וְאֵת כָּל־עוֹף כָּנָף לְמִינֵהוּ וַיַּרְא אֱלֹהִים כִּי־טוֹב׃
וַיְבָרֶךְ אֹתָם אֱלֹהִים לֵאמֹר פְּרוּ וּרְבוּ וּמִלְאוּ אֶת־הַמַּיִם בַּיַּמִּים וְהָעוֹף יִרֶב בָּאָרֶץ׃
וַיְהִי־עֶרֶב וַיְהִי־בֹקֶר יוֹם חֲמִישִׁי׃
וַיֹּאמֶר אֱלֹהִים תּוֹצֵא הָאָרֶץ נֶפֶשׁ חַיָּה לְמִינָהּ בְּהֵמָה וָרֶמֶשׂ וְחַיְתוֹ־אֶרֶץ לְמִינָהּ וַיְהִי־כֵן׃
וַיַּעַשׂ אֱלֹהִים אֶת־חַיַּת הָאָרֶץ לְמִינָהּ וְאֶת־הַבְּהֵמָה לְמִינָהּ וְאֵת כָּל־רֶמֶשׂ הָאֲדָמָה לְמִינֵהוּ וַיַּרְא אֱלֹהִים כִּי־טוֹב׃
וַיֹּאמֶר אֱלֹהִים נַעֲשֶׂה אָדָם בְּצַלְמֵנוּ כִּדְמוּתֵנוּ וְיִרְדּוּ בִדְגַת הַיָּם וּבְעוֹף הַשָּׁמַיִם וּבַבְּהֵמָה וּבְכָל־הָאָרֶץ וּבְכָל־הָרֶמֶשׂ הָרֹמֵשׂ עַל־הָאָרֶץ׃
וַיִּבְרָא אֱלֹהִים אֶת־הָאָדָם בְּצַלְמוֹ בְּצֶלֶם אֱלֹהִים בָּרָא אֹתוֹ זָכָר וּנְקֵבָה בָּרָא אֹתָם׃
וַיְבָרֶךְ אֹתָם אֱלֹהִים וַיֹּאמֶר לָהֶם אֱלֹהִים פְּרוּ וּרְבוּ וּמִלְאוּ אֶת־הָאָרֶץ וְכִבְשֻׁהָ וּרְדוּ בִּדְגַת הַיָּם וּבְעוֹף הַשָּׁמַיִם וּבְכָל־חַיָּה הָרֹמֶשֶׂת עַל־הָאָרֶץ׃
וַיֹּאמֶר אֱלֹהִים הִנֵּה נָתַתִּי לָכֶם אֶת־כָּל־עֵשֶׂב זֹרֵעַ זֶרַע אֲשֶׁר עַל־פְּנֵי כָל־הָאָרֶץ וְאֶת־כָּל־הָעֵץ אֲשֶׁר־בּוֹ פְרִי־עֵץ זֹרֵעַ זָרַע לָכֶם יִהְיֶה לְאָכְלָה׃
וּלְכָל־חַיַּת הָאָרֶץ וּלְכָל־עוֹף הַשָּׁמַיִם וּלְכֹל רוֹמֵשׂ עַל־הָאָרֶץ אֲשֶׁר־בּוֹ נֶפֶשׁ חַיָּה אֶת־כָּל־יֶרֶק עֵשֶׂב לְאָכְלָה וַיְהִי־כֵן׃
וַיַּרְא אֱלֹהִים אֶת־כָּל־אֲשֶׁר עָשָׂה וְהִנֵּה־טוֹב מְאֹד וַיְהִי־עֶרֶב וַיְהִי־בֹקֶר יוֹם הַשִּׁשִּׁי׃

Chapter 2

וַיְכֻלּוּ הַשָּׁמַיִם וְהָאָרֶץ וְכָל־צְבָאָם׃
וַיְכַל אֱלֹהִים בַּיּוֹם הַשְּׁבִיעִי מְלַאכְתּוֹ אֲשֶׁר עָשָׂה וַיִּשְׁבֹּת בַּיּוֹם הַשְּׁבִיעִי מִכָּל־מְלַאכְתּוֹ אֲשֶׁר עָשָׂה׃
וַיְבָרֶךְ אֱלֹהִים אֶת־יוֹם הַשְּׁבִיעִי וַיְקַדֵּשׁ אֹתוֹ כִּי בוֹ שָׁבַת מִכָּל־מְלַאכְתּוֹ אֲשֶׁר־בָּרָא אֱלֹהִים לַעֲשׂוֹת׃
אֵלֶּה תוֹלְדוֹת הַשָּׁמַיִם וְהָאָרֶץ בְּהִבָּרְאָם בְּיוֹם עֲשׂוֹת יְהוָה אֱלֹהִים אֶרֶץ וְשָׁמָיִם׃
וְכֹל שִׂיחַ הַשָּׂדֶה טֶרֶם יִהְיֶה בָאָרֶץ וְכָל־עֵשֶׂב הַשָּׂדֶה טֶרֶם יִצְמָח כִּי לֹא הִמְטִיר יְהוָה אֱלֹהִים עַל־הָאָרֶץ וְאָדָם אַיִן לַעֲבֹד אֶת־הָאֲדָמָה׃
וְאֵד יַעֲלֶה מִן־הָאָרֶץ וְהִשְׁקָה אֶת־כָּל־פְּנֵי־הָאֲדָמָה׃
וַיִּיצֶר יְהוָה אֱלֹהִים אֶת־הָאָדָם עָפָר מִן־הָאֲדָמָה וַיִּפַּח בְּאַפָּיו נִשְׁמַת חַיִּים וַיְהִי הָאָדָם לְנֶפֶשׁ חַיָּה׃
וַיִּטַּע יְהוָה אֱלֹהִים גַּן־בְעֵדֶן מִקֶּדֶם וַיָּשֶׂם שָׁם אֶת־הָאָדָם אֲשֶׁר יָצָר׃
וַיַּצְמַח יְהוָה אֱלֹהִים מִן־הָאֲדָמָה כָּל־עֵץ נֶחְמָד לְמַרְאֶה וְטוֹב לְמַאֲכָל וְעֵץ הַחַיִּים בְּתוֹךְ הַגָּן וְעֵץ הַדַּעַת טוֹב וָרָע׃
וְנָהָרּ יֹצֵא מֵעֵדֶן לְהַשְׁקוֹת אֶת־הַגָּן וּמִשָּׁם יִפָּרֵד וְהָיָה לְאַרְבָּעָה רָאשִׁים׃
שֵׁם הָאֶחָד פִּישׁוֹן הוּא הַסֹּבֵב אֵת כָּל־אֶרֶץ הַחֲוִילָה אֲשֶׁר־שָׁם הַזָּהָב׃
וּזֲהַב הָאָרֶץ הַהִוא טוֹב שָׁם הַבְּדֹלַח וְאֶבֶן הַשֹּׁהַם׃
וְשֵׁם־הַנָּהָר הַשֵּׁנִי גִּיחוֹן הוּא הַסּוֹבֵב אֵת כָּל־אֶרֶץ כּוּשׁ׃
וְשֵׁם הַנָּהָר הַשְּׁלִישִׁי חִדֶּקֶל הוּא הַהֹלֵךְ קִדְמַת אַשּׁוּר וְהַנָּהָר הָרְבִיעִי הוּא פְרָת׃
וַיִּקַּח יְהוָה אֱלֹהִים אֶת־הָאָדָם וַיַּנִּחֵהוּ בְגַן־עֵדֶן לְעָבְדָהּ וּלְשָׁמְרָהּ׃
וַיְצַו יְהוָה אֱלֹהִים עַל־הָאָדָם לֵאמֹר מִכֹּל עֵץ־הַגָּן אָכֹל תֹּאכֵל׃
וּמֵעֵץ הַדַּעַת טוֹב וָרָע לֹא תֹאכַל מִמֶּנּוּ כִּי בְּיוֹם אֲכָלְךָ מִמֶּנּוּ מוֹת תָּמוּת׃
וַיֹּאמֶר יְהוָה אֱלֹהִים לֹא־טוֹב הֱיוֹת הָאָדָם לְבַדּוֹ אֶעֱשֶׂהּ־לּוֹ עֵזֶר כְּנֶגְדּוֹ׃
וַיִּצֶר יְהוָה אֱלֹהִים מִן־הָאֲדָמָה כָּל־חַיַּת הַשָּׂדֶה וְאֵת כָּל־עוֹף הַשָּׁמַיִם וַיָּבֵא אֶל־הָאָדָם לִרְאוֹת מַה־יִּקְרָא־לוֹ וְכֹל אֲשֶׁר יִקְרָא־לוֹ הָאָדָם נֶפֶשׁ חַיָּה הוּא שְׁמוֹ׃
וַיִּקְרָא הָאָדָם שֵׁמוֹת לְכָל־הַבְּהֵמָה וּלְעוֹף הַשָּׁמַיִם וּלְכֹל חַיַּת הַשָּׂדֶה וּלְאָדָם לֹא־מָצָא עֵזֶר כְּנֶגְדּוֹ׃
וַיַּפֵּל יְהוָה אֱלֹהִים תַּרְדֵּמָה עַל־הָאָדָם וַיִּישָׁן וַיִּקַּח אַחַת מִצַּלְעֹתָיו וַיִּסְגֹּר בָּשָׂר תַּחְתֶּנָּה׃
וַיִּבֶן יְהוָה אֱלֹהִים אֶת־הַצֵּלָע אֲשֶׁר־לָקַח מִן־הָאָדָם לְאִשָּׁה וַיְבִאֶהָ אֶל־הָאָדָם׃
וַיֹּאמֶר הָאָדָם זֹאת הַפַּעַם עֶצֶם מֵעֲצָמַי וּבָשָׂר מִבְּשָׂרִי לְזֹאת יִקָּרֵא אִשָּׁה כִּי מֵאִישׁ לֻקֳחָה־זֹּאת׃
עַל־כֵּן יַעֲזָב־אִישׁ אֶת־אָבִיו וְאֶת־אִמּוֹ וְדָבַק בְּאִשְׁתּוֹ וְהָיוּ לְבָשָׂר אֶחָד׃
וַיִּהְיוּ שְׁנֵיהֶם עֲרוּמִּים הָאָדָם וְאִשְׁתּוֹ וְלֹא יִתְבֹּשָׁשׁוּ׃

Chapter 3

וְהַנָּחָשׁ הָיָה עָרוּם מִכֹּל חַיַּת הַשָּׂדֶה אֲשֶׁר עָשָׂה יְהוָה אֱלֹהִים וַיֹּאמֶר אֶל־הָאִשָּׁה אַף כִּי־אָמַר אֱלֹהִים לֹא תֹאכְלוּ מִכֹּל עֵץ הַגָּן׃
וַתֹּאמֶר הָאִשָּׁה אֶל־הַנָּחָשׁ מִפְּרִי עֵץ־הַגָּן נֹאכֵל׃
וּמִפְּרִי הָעֵץ אֲשֶׁר בְּתוֹךְ־הַגָּן אָמַר אֱלֹהִים לֹא תֹאכְלוּ מִמֶּנּוּ וְלֹא תִגְּעוּ בּוֹ פֶּן־תְּמֻתוּן׃
וַיֹּאמֶר הַנָּחָשׁ אֶל־הָאִשָּׁה לֹא־מוֹת תְּמֻתוּן׃
כִּי יֹדֵעַ אֱלֹהִים כִּי בְּיוֹם אֲכָלְכֶם מִמֶּנּוּ וְנִפְקְחוּ עֵינֵיכֶם וִהְיִיתֶם כֵּאלֹהִים יֹדְעֵי טוֹב וָרָע׃
וַתֵּרֶא הָאִשָּׁה כִּי טוֹב הָעֵץ לְמַאֲכָל וְכִי תַאֲוָה־הוּא לָעֵינַיִם וְנֶחְמָד הָעֵץ לְהַשְׂכִּיל וַתִּקַּח מִפִּרְיוֹ וַתֹּאכַל וַתִּתֵּן גַּם־לְאִישָׁהּ עִמָּהּ וַיֹּאכַל׃
וַתִּפָּקַחְנָה עֵינֵי שְׁנֵיהֶם וַיֵּדְעוּ כִּי עֵירֻמִּם הֵם וַיִּתְפְּרוּ עֲלֵה תְאֵנָה וַיַּעֲשׂוּ לָהֶם חֲגֹרֹת׃
וַיִּשְׁמְעוּ אֶת־קוֹל יְהוָה אֱלֹהִים מִתְהַלֵּךְ בַּגָּן לְרוּחַ הַיּוֹם וַיִּתְחַבֵּא הָאָדָם וְאִשְׁתּוֹ מִפְּנֵי יְהוָה אֱלֹהִים בְּתוֹךְ עֵץ הַגָּן׃
וַיִּקְרָא יְהוָה אֱלֹהִים אֶל־הָאָדָם וַיֹּאמֶר לוֹ אַיֶּכָּה׃
וַיֹּאמֶר אֶת־קֹלְךָ שָׁמַעְתִּי בַּגָּן וָאִירָא כִּי־עֵירֹם אָנֹכִי וָאֵחָבֵא׃
וַיֹּאמֶר מִי הִגִּיד לְךָ כִּי עֵירֹם אָתָּה הֲמִן־הָעֵץ אֲשֶׁר צִוִּיתִיךָ לְבִלְתִּי אֲכָל־מִמֶּנּוּ אָכָלְתָּ׃
וַיֹּאמֶר הָאָדָם הָאִשָּׁה אֲשֶׁר נָתַתָּה עִמָּדִי הִוא נָתְנָה־לִּי מִן־הָעֵץ וָאֹכֵל׃
וַיֹּאמֶר יְהוָה אֱלֹהִים לָאִשָּׁה מַה־זֹּאת עָשִׂית וַתֹּאמֶר הָאִשָּׁה הַנָּחָשׁ הִשִּׁיאַנִי וָאֹכֵל׃
וַיֹּאמֶר יְהֹוָה אֱלֹהִים אֶל־הַנָּחָשׁ כִּי עָשִׂיתָ זֹּאת אָרוּר אַתָּה מִכָּל־הַבְּהֵמָה וּמִכֹּל חַיַּת הַשָּׂדֶה עַל־גְּחֹנְךָ תֵלֵךְ וְעָפָר תֹּאכַל כָּל־יְמֵי חַיֶּיךָ׃
וְאֵיבָה אָשִׁית בֵּינְךָ וּבֵין הָאִשָּׁה וּבֵין זַרְעֲךָ וּבֵין זַרְעָהּ הוּא יְשׁוּפְךָ רֹאשׁ וְאַתָּה תְּשׁוּפֶנּוּ עָקֵב׃
אֶל־הָאִשָּׁה אָמַר הַרְבָּה אַרְבֶּה עִצְּבוֹנֵךְ וְהֵרֹנֵךְ בְּעֶצֶב תֵּלְדִי בָנִים וְאֶל־אִישֵׁךְ תְּשׁוּקָתֵךְ וְהוּא יִמְשָׁל־בָּךְ׃
וּלְאָדָם אָמַר כִּי־שָׁמַעְתָּ לְקוֹל אִשְׁתֶּךָ וַתֹּאכַל מִן־הָעֵץ אֲשֶׁר צִוִּיתִיךָ לֵאמֹר לֹא תֹאכַל מִמֶּנּוּ אֲרוּרָה הָאֲדָמָה בַּעֲבוּרֶךָ בְּעִצָּבוֹן תֹּאכֲלֶנָּה כֹּל יְמֵי חַיֶּיךָ׃
וְקוֹץ וְדַרְדַּר תַּצְמִיחַ לָךְ וְאָכַלְתָּ אֶת־עֵשֶׂב הַשָּׂדֶה׃
בְּזֵעַת אַפֶּיךָ תֹּאכַל לֶחֶם עַד שׁוּבְךָ אֶל־הָאֲדָמָה כִּי מִמֶּנָּה לֻקָּחְתָּ כִּי־עָפָר אַתָּה וְאֶל־עָפָר תָּשׁוּב׃
וַיִּקְרָא הָאָדָם שֵׁם אִשְׁתּוֹ חַוָּה כִּי הִוא הָיְתָה אֵם כָּל־חָי׃
וַיַּעַשׂ יְהוָה אֱלֹהִים לְאָדָם וּלְאִשְׁתּוֹ כָּתְנוֹת עוֹר וַיַּלְבִּשֵׁם׃
וַיֹּאמֶר יְהוָה אֱלֹהִים הֵן הָאָדָם הָיָה כְּאַחַד מִמֶּנּוּ לָדַעַת טוֹב וָרָע וְעַתָּה פֶּן־יִשְׁלַח יָדוֹ וְלָקַח גַּם מֵעֵץ הַחַיִּים וְאָכַל וָחַי לְעֹלָם׃
וַיְשַׁלְּחֵהוּ יְהוָה אֱלֹהִים מִגַּן־עֵדֶן לַעֲבֹד אֶת־הָאֲדָמָה אֲשֶׁר לֻקַּח מִשָּׁם׃
וַיְגָרֶשׁ אֶת־הָאָדָם וַיַּשְׁכֵּן מִקֶּדֶם לְגַן־עֵדֶן אֶת־הַכְּרֻבִים וְאֵת לַהַט הַחֶרֶב הַמִּתְהַפֶּכֶת לִשְׁמֹר אֶת־דֶּרֶךְ עֵץ הַחַיִּים׃

Chapter 4

וְהָאָדָם יָדַע אֶת־חַוָּה אִשְׁתּוֹ וַתַּהַר וַתֵּלֶד אֶת־קַיִן וַתֹּאמֶר קָנִיתִי אִישׁ אֶת־יְהוָה׃
וַתֹּסֶף לָלֶדֶת אֶת־אָחִיו אֶת־הָבֶל וַיְהִי־הֶבֶל רֹעֵה צֹאן וְקַיִן הָיָה עֹבֵד אֲדָמָה׃
וַיְהִי מִקֵּץ יָמִים וַיָּבֵא קַיִן מִפְּרִי הָאֲדָמָה מִנְחָה לַיהוָה׃
וְהֶבֶל הֵבִיא גַם־הוּא מִבְּכֹרוֹת צֹאנוֹ וּמֵחֶלְבֵהֶן וַיִּשַׁע יְהוָה אֶל־הֶבֶל וְאֶל־מִנְחָתוֹ׃
וְאֶל־קַיִן וְאֶל־מִנְחָתוֹ לֹא שָׁעָה וַיִּחַר לְקַיִן מְאֹד וַיִּפְּלוּ פָּנָיו׃
וַיֹּאמֶר יְהוָה אֶל־קָיִן לָמָּה חָרָה לָךְ וְלָמָּה נָפְלוּ פָנֶיךָ׃
הֲלוֹא אִם־תֵּיטִיב שְׂאֵת וְאִם לֹא תֵיטִיב לַפֶּתַח חַטָּאת רֹבֵץ וְאֵלֶיךָ תְּשׁוּקָתוֹ וְאַתָּה תִּמְשָׁל־בּוֹ׃
וַיֹּאמֶר קַיִן אֶל־הֶבֶל אָחִיו וַיְהִי בִּהְיוֹתָם בַּשָּׂדֶה וַיָּקָם קַיִן אֶל־הֶבֶל אָחִיו וַיַּהַרְגֵהוּ׃
וַיֹּאמֶר יְהוָה אֶל־קַיִן אֵי הֶבֶל אָחִיךָ וַיֹּאמֶר לֹא יָדַעְתִּי הֲשֹׁמֵר אָחִי אָנֹכִי׃
וַיֹּאמֶר מֶה עָשִׂיתָ קוֹל דְּמֵי אָחִיךָ צֹעֲקִים אֵלַי מִן־הָאֲדָמָה׃
וְעַתָּה אָרוּר אָתָּה מִן־הָאֲדָמָה אֲשֶׁר פָּצְתָה אֶת־פִּיהָ לָקַחַת אֶת־דְּמֵי אָחִיךָ מִיָּדֶךָ׃
כִּי תַעֲבֹד אֶת־הָאֲדָמָה לֹא־תֹסֵף תֵּת־כֹּחָהּ לָךְ נָע וָנָד תִּהְיֶה בָאָרֶץ׃
וַיֹּאמֶר קַיִן אֶל־יְהוָה גָּדוֹל עֲוֺנִי מִנְּשֹׂא׃
הֵן גֵּרַשְׁתָּ אֹתִי הַיּוֹם מֵעַל פְּנֵי הָאֲדָמָה וּמִפָּנֶיךָ אֶסָּתֵר וְהָיִיתִי נָע וָנָד בָּאָרֶץ וְהָיָה כָל־מֹצְאִי יַהַרְגֵנִי׃
וַיֹּאמֶר לוֹ יְהוָה לָכֵן כָּל־הֹרֵג קַיִן שִׁבְעָתַיִם יֻקָּם וַיָּשֶׂם יְהוָה לְקַיִן אוֹת לְבִלְתִּי הַכּוֹת־אֹתוֹ כָּל־מֹצְאוֹ׃
וַיֵּצֵא קַיִן מִלִּפְנֵי יְהוָה וַיֵּשֶׁב בְּאֶרֶץ־נוֹד קִדְמַת־עֵדֶן׃
וַיֵּדַע קַיִן אֶת־אִשְׁתּוֹ וַתַּהַר וַתֵּלֶד אֶת־חֲנוֹךְ וַיְהִי בֹּנֶה עִיר וַיִּקְרָא שֵׁם הָעִיר כְּשֵׁם בְּנוֹ חֲנוֹךְ׃
וַיִּוָּלֵד לַחֲנוֹךְ אֶת־עִירָד וְעִירָד יָלַד אֶת־מְחוּיָאֵל וּמְחִיּיָאֵל יָלַד אֶת־מְתוּשָׁאֵל וּמְתוּשָׁאֵל יָלַד אֶת־לָמֶךְ׃
וַיִּקַּח־לוֹ לֶמֶךְ שְׁתֵּי נָשִׁים שֵׁם הָאַחַת עָדָה וְשֵׁם הַשֵּׁנִית צִלָּה׃
וַתֵּלֶד עָדָה אֶת־יָבָל הוּא הָיָה אֲבִי יֹשֵׁב אֹהֶל וּמִקְנֶה׃
וְשֵׁם אָחִיו יוּבָל הוּא הָיָה אֲבִי כָּל־תֹּפֵשׂ כִּנּוֹר וְעוּגָב׃
וְצִלָּה גַם־הִוא יָלְדָה אֶת־תּוּבַל קַיִן לֹטֵשׁ כָּל־חֹרֵשׁ נְחֹשֶׁת וּבַרְזֶל וַאֲחוֹת תּוּבַל־קַיִן נַעֲמָה׃
וַיֹּאמֶר לֶמֶךְ לְנָשָׁיו עָדָה וְצִלָּה שְׁמַעַן קוֹלִי נְשֵׁי לֶמֶךְ הַאְזֵנָּה אִמְרָתִי כִּי אִישׁ הָרַגְתִּי לְפִצְעִי וְיֶלֶד לְחַבֻּרָתִי׃
כִּי שִׁבְעָתַיִם יֻקַּם־קָיִן וְלֶמֶךְ שִׁבְעִים וְשִׁבְעָה׃
וַיֵּדַע אָדָם עוֹד אֶת־אִשְׁתּוֹ וַתֵּלֶד בֵּן וַתִּקְרָא אֶת־שְׁמוֹ שֵׁת כִּי שָׁת־לִי אֱלֹהִים זֶרַע אַחֵר תַּחַת הֶבֶל כִּי הֲרָגוֹ קָיִן׃
וּלְשֵׁת גַּם־הוּא יֻלַּד־בֵּן וַיִּקְרָא אֶת־שְׁמוֹ אֱנוֹשׁ אָז הוּחַל לִקְרֹא בְּשֵׁם יְהוָה׃

Chapter 5

זֶה סֵפֶר תּוֹלְדֹת אָדָם בְּיוֹם בְּרֹא אֱלֹהִים אָדָם בִּדְמוּת אֱלֹהִים עָשָׂה אֹתוֹ׃
זָכָר וּנְקֵבָה בְּרָאָם וַיְבָרֶךְ אֹתָם וַיִּקְרָא אֶת־שְׁמָם אָדָם בְּיוֹם הִבָּרְאָם׃
וַיְחִי אָדָם שְׁלֹשִׁים וּמְאַת שָׁנָה וַיּוֹלֶד בִּדְמוּתוֹ כְּצַלְמוֹ וַיִּקְרָא אֶת־שְׁמוֹ שֵׁת׃
וַיִּהְיוּ יְמֵי־אָדָם אַחֲרֵי הוֹלִידוֹ אֶת־שֵׁת שְׁמֹנֶה מֵאֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיִּהְיוּ כָּל־יְמֵי אָדָם אֲשֶׁר־חַי תְּשַׁע מֵאוֹת שָׁנָה וּשְׁלֹשִׁים שָׁנָה וַיָּמֹת׃
וַיְחִי־שֵׁת חָמֵשׁ שָׁנִים וּמְאַת שָׁנָה וַיּוֹלֶד אֶת־אֱנוֹשׁ׃
וַיְחִי־שֵׁת אַחֲרֵי הוֹלִידוֹ אֶת־אֱנוֹשׁ שֶׁבַע שָׁנִים וּשְׁמֹנֶה מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיִּהְיוּ כָּל־יְמֵי־שֵׁת שְׁתֵּים עֶשְׂרֵה שָׁנָה וּתְשַׁע מֵאוֹת שָׁנָה וַיָּמֹת׃
וַיְחִי אֱנוֹשׁ תִּשְׁעִים שָׁנָה וַיּוֹלֶד אֶת־קֵינָן׃
וַיְחִי אֱנוֹשׁ אַחֲרֵי הוֹלִידוֹ אֶת־קֵינָן חֲמֵשׁ עֶשְׂרֵה שָׁנָה וּשְׁמֹנֶה מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיִּהְיוּ כָּל־יְמֵי אֱנוֹשׁ חָמֵשׁ שָׁנִים וּתְשַׁע מֵאוֹת שָׁנָה וַיָּמֹת׃
וַיְחִי קֵינָן שִׁבְעִים שָׁנָה וַיּוֹלֶד אֶת־מַהֲלַלְאֵל׃
וַיְחִי קֵינָן אַחֲרֵי הוֹלִידוֹ אֶת־מַהֲלַלְאֵל אַרְבָּעִים שָׁנָה וּשְׁמֹנֶה מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיִּהְיוּ כָּל־יְמֵי קֵינָן עֶשֶׂר שָׁנִים וּתְשַׁע מֵאוֹת שָׁנָה וַיָּמֹת׃
וַיְחִי מַהֲלַלְאֵל חָמֵשׁ שָׁנִים וְשִׁשִּׁים שָׁנָה וַיּוֹלֶד אֶת־יָרֶד׃
וַיְחִי מַהֲלַלְאֵל אַחֲרֵי הוֹלִידוֹ אֶת־יֶרֶד שְׁלֹשִׁים שָׁנָה וּשְׁמֹנֶה מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיִּהְיוּ כָּל־יְמֵי מַהֲלַלְאֵל חָמֵשׁ וְתִשְׁעִים שָׁנָה וּשְׁמֹנֶה מֵאוֹת שָׁנָה וַיָּמֹת׃
וַיְחִי־יֶרֶד שְׁתַּיִם וְשִׁשִּׁים שָׁנָה וּמְאַת שָׁנָה וַיּוֹלֶד אֶת־חֲנוֹךְ׃
וַיְחִי־יֶרֶד אַחֲרֵי הוֹלִידוֹ אֶת־חֲנוֹךְ שְׁמֹנֶה מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיִּהְיוּ כָּל־יְמֵי־יֶרֶד שְׁתַּיִם וְשִׁשִּׁים שָׁנָה וּתְשַׁע מֵאוֹת שָׁנָה וַיָּמֹת׃
וַיְחִי חֲנוֹךְ חָמֵשׁ וְשִׁשִּׁים שָׁנָה וַיּוֹלֶד אֶת־מְתוּשָׁלַח׃
וַיִּתְהַלֵּךְ חֲנוֹךְ אֶת־הָאֱלֹהִים אַחֲרֵי הוֹלִידוֹ אֶת־מְתוּשֶׁלַח שְׁלֹשׁ מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְהִי כָּל־יְמֵי חֲנוֹךְ חָמֵשׁ וְשִׁשִּׁים שָׁנָה וּשְׁלֹשׁ מֵאוֹת שָׁנָה׃
וַיִּתְהַלֵּךְ חֲנוֹךְ אֶת־הָאֱלֹהִים וְאֵינֶנּוּ כִּי־לָקַח אֹתוֹ אֱלֹהִים׃
וַיְחִי מְתוּשֶׁלַח שֶׁבַע וּשְׁמֹנִים שָׁנָה וּמְאַת שָׁנָה וַיּוֹלֶד אֶת־לָמֶךְ׃
וַיְחִי מְתוּשֶׁלַח אַחֲרֵי הוֹלִידוֹ אֶת־לֶמֶךְ שְׁתַּיִם וּשְׁמוֹנִים שָׁנָה וּשְׁבַע מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיִּהְיוּ כָּל־יְמֵי מְתוּשֶׁלַח תֵּשַׁע וְשִׁשִּׁים שָׁנָה וּתְשַׁע מֵאוֹת שָׁנָה וַיָּמֹת׃
וַיְחִי־לֶמֶךְ שְׁתַּיִם וּשְׁמֹנִים שָׁנָה וּמְאַת שָׁנָה וַיּוֹלֶד בֵּן׃
וַיִּקְרָא אֶת־שְׁמוֹ נֹחַ לֵאמֹר זֶה יְנַחֲמֵנוּ מִמַּעֲשֵׂנוּ וּמֵעִצְּבוֹן יָדֵינוּ מִן־הָאֲדָמָה אֲשֶׁר אֵרְרָהּ יְהוָה׃
וַיְחִי־לֶמֶךְ אַחֲרֵי הוֹלִידוֹ אֶת־נֹחַ חָמֵשׁ וְתִשְׁעִים שָׁנָה וַחֲמֵשׁ מֵאֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְהִי כָּל־יְמֵי־לֶמֶךְ שֶׁבַע וְשִׁבְעִים שָׁנָה וּשְׁבַע מֵאוֹת שָׁנָה וַיָּמֹת׃
וַיְהִי־נֹחַ בֶּן־חֲמֵשׁ מֵאוֹת שָׁנָה וַיּוֹלֶד נֹחַ אֶת־שֵׁם אֶת־חָם וְאֶת־יָפֶת׃

Chapter 6

וַיְהִי כִּי־הֵחֵל הָאָדָם לָרֹב עַל־פְּנֵי הָאֲדָמָה וּבָנוֹת יֻלְּדוּ לָהֶם׃
וַיִּרְאוּ בְנֵי־הָאֱלֹהִים אֶת־בְּנוֹת הָאָדָם כִּי טֹבֹת הֵנָּה וַיִּקְחוּ לָהֶם נָשִׁים מִכֹּל אֲשֶׁר בָּחָרוּ׃
וַיֹּאמֶר יְהוָה לֹא־יָדוֹן רוּחִי בָאָדָם לְעֹלָם בְּשַׁגַּם הוּא בָשָׂר וְהָיוּ יָמָיו מֵאָה וְעֶשְׂרִים שָׁנָה׃
הַנְּפִלִים הָיוּ בָאָרֶץ בַּיָּמִים הָהֵם וְגַם אַחֲרֵי־כֵן אֲשֶׁר יָבֹאוּ בְּנֵי הָאֱלֹהִים אֶל־בְּנוֹת הָאָדָם וְיָלְדוּ לָהֶם הֵמָּה הַגִּבֹּרִים אֲשֶׁר מֵעוֹלָם אַנְשֵׁי הַשֵּׁם׃
וַיַּרְא יְהוָה כִּי רַבָּה רָעַת הָאָדָם בָּאָרֶץ וְכָל־יֵצֶר מַחְשְׁבֹת לִבּוֹ רַק רַע כָּל־הַיּוֹם׃
וַיִּנָּחֶם יְהוָה כִּי־עָשָׂה אֶת־הָאָדָם בָּאָרֶץ וַיִּתְעַצֵּב אֶל־לִבּוֹ׃
וַיֹּאמֶר יְהוָה אֶמְחֶה אֶת־הָאָדָם אֲשֶׁר־בָּרָאתִי מֵעַל פְּנֵי הָאֲדָמָה מֵאָדָם עַד־בְּהֵמָה עַד־רֶמֶשׂ וְעַד־עוֹף הַשָּׁמָיִם כִּי נִחַמְתִּי כִּי עֲשִׂיתִם׃
וְנֹחַ מָצָא חֵן בְּעֵינֵי יְהוָה׃
אֵלֶּה תּוֹלְדֹת נֹחַ נֹחַ אִישׁ צַדִּיק תָּמִים הָיָה בְּדֹרֹתָיו אֶת־הָאֱלֹהִים הִתְהַלֶּךְ־נֹחַ׃
וַיּוֹלֶד נֹחַ שְׁלֹשָׁה בָנִים אֶת־שֵׁם אֶת־חָם וְאֶת־יָפֶת׃
וַתִּשָּׁחֵת הָאָרֶץ לִפְנֵי הָאֱלֹהִים וַתִּמָּלֵא הָאָרֶץ חָמָס׃
וַיַּרְא אֱלֹהִים אֶת־הָאָרֶץ וְהִנֵּה נִשְׁחָתָה כִּי־הִשְׁחִית כָּל־בָּשָׂר אֶת־דַּרְכּוֹ עַל־הָאָרֶץ׃
וַיֹּאמֶר אֱלֹהִים לְנֹחַ קֵץ כָּל־בָּשָׂר בָּא לְפָנַי כִּי־מָלְאָה הָאָרֶץ חָמָס מִפְּנֵיהֶם וְהִנְנִי מַשְׁחִיתָם אֶת־הָאָרֶץ׃
עֲשֵׂה לְךָ תֵּבַת עֲצֵי־גֹפֶר קִנִּים תַּעֲשֶׂה אֶת־הַתֵּבָה וְכָפַרְתָּ אֹתָהּ מִבַּיִת וּמִחוּץ בַּכֹּפֶר׃
וְזֶה אֲשֶׁר תַּעֲשֶׂה אֹתָהּ שְׁלֹשׁ מֵאוֹת אַמָּה אֹרֶךְ הַתֵּבָה חֲמִשִּׁים אַמָּה רָחְבָּהּ וּשְׁלֹשִׁים אַמָּה קוֹמָתָהּ׃
צֹהַר תַּעֲשֶׂה לַתֵּבָה וְאֶל־אַמָּה תְּכַלֶנָּה מִלְמַעְלָה וּפֶתַח הַתֵּבָה בְּצִדָּהּ תָּשִׂים תַּחְתִּיִּם שְׁנִיִּם וּשְׁלִשִׁים תַּעֲשֶׂהָ׃
וַאֲנִי הִנְנִי מֵבִיא אֶת־הַמַּבּוּל מַיִם עַל־הָאָרֶץ לְשַׁחֵת כָּל־בָּשָׂר אֲשֶׁר־בּוֹ רוּחַ חַיִּים מִתַּחַת הַשָּׁמָיִם כֹּל אֲשֶׁר־בָּאָרֶץ יִגְוָע׃
וַהֲקִמֹתִי אֶת־בְּרִיתִי אִתָּךְ וּבָאתָ אֶל־הַתֵּבָה אַתָּה וּבָנֶיךָ וְאִשְׁתְּךָ וּנְשֵׁי־בָנֶיךָ אִתָּךְ׃
וּמִכָּל־הָחַי מִכָּל־בָּשָׂר שְׁנַיִם מִכֹּל תָּבִיא אֶל־הַתֵּבָה לְהַחֲיֹת אִתָּךְ זָכָר וּנְקֵבָה יִהְיוּ׃
מֵהָעוֹף לְמִינֵהוּ וּמִן־הַבְּהֵמָה לְמִינָהּ מִכֹּל רֶמֶשׂ הָאֲדָמָה לְמִינֵהוּ שְׁנַיִם מִכֹּל יָבֹאוּ אֵלֶיךָ לְהַחֲיוֹת׃
וְאַתָּה קַח־לְךָ מִכָּל־מַאֲכָל אֲשֶׁר יֵאָכֵל וְאָסַפְתָּ אֵלֶיךָ וְהָיָה לְךָ וְלָהֶם לְאָכְלָה׃
וַיַּעַשׂ נֹחַ כְּכֹל אֲשֶׁר צִוָּה אֹתוֹ אֱלֹהִים כֵּן עָשָׂה׃

Chapter 7

וַיֹּאמֶר יְהוָה לְנֹחַ בֹּא־אַתָּה וְכָל־בֵּיתְךָ אֶל־הַתֵּבָה כִּי־אֹתְךָ רָאִיתִי צַדִּיק לְפָנַי בַּדּוֹר הַזֶּה׃
מִכֹּל הַבְּהֵמָה הַטְּהוֹרָה תִּקַּח־לְךָ שִׁבְעָה שִׁבְעָה אִישׁ וְאִשְׁתּוֹ וּמִן־הַבְּהֵמָה אֲשֶׁר לֹא טְהֹרָה הִוא שְׁנַיִם אִישׁ וְאִשְׁתּוֹ׃
גַּם מֵעוֹף הַשָּׁמַיִם שִׁבְעָה שִׁבְעָה זָכָר וּנְקֵבָה לְחַיּוֹת זֶרַע עַל־פְּנֵי כָל־הָאָרֶץ׃
כִּי לְיָמִים עוֹד שִׁבְעָה אָנֹכִי מַמְטִיר עַל־הָאָרֶץ אַרְבָּעִים יוֹם וְאַרְבָּעִים לָיְלָה וּמָחִיתִי אֶת־כָּל־הַיְקוּם אֲשֶׁר עָשִׂיתִי מֵעַל פְּנֵי הָאֲדָמָה׃
וַיַּעַשׂ נֹחַ כְּכֹל אֲשֶׁר־צִוָּהוּ יְהוָה׃
וְנֹחַ בֶּן־שֵׁשׁ מֵאוֹת שָׁנָה וְהַמַּבּוּל הָיָה מַיִם עַל־הָאָרֶץ׃
וַיָּבֹא נֹחַ וּבָנָיו וְאִשְׁתּוֹ וּנְשֵׁי־בָנָיו אִתּוֹ אֶל־הַתֵּבָה מִפְּנֵי מֵי הַמַּבּוּל׃
מִן־הַבְּהֵמָה הַטְּהוֹרָה וּמִן־הַבְּהֵמָה אֲשֶׁר אֵינֶנָּה טְהֹרָה וּמִן־הָעוֹף וְכֹל אֲשֶׁר־רֹמֵשׂ עַל־הָאֲדָמָה׃
שְׁנַיִם שְׁנַיִם בָּאוּ אֶל־נֹחַ אֶל־הַתֵּבָה זָכָר וּנְקֵבָה כַּאֲשֶׁר צִוָּה אֱלֹהִים אֶת־נֹחַ׃
וַיְהִי לְשִׁבְעַת הַיָּמִים וּמֵי הַמַּבּוּל הָיוּ עַל־הָאָרֶץ׃
בִּשְׁנַת שֵׁשׁ־מֵאוֹת שָׁנָה לְחַיֵּי־נֹחַ בַּחֹדֶשׁ הַשֵּׁנִי בְּשִׁבְעָה־עָשָׂר יוֹם לַחֹדֶשׁ בַּיּוֹם הַזֶּה נִבְקְעוּ כָּל־מַעְיְנֹת תְּהוֹם רַבָּה וַאֲרֻבֹּת הַשָּׁמַיִם נִפְתָּחוּ׃
וַיְהִי הַגֶּשֶׁם עַל־הָאָרֶץ אַרְבָּעִים יוֹם וְאַרְבָּעִים לָיְלָה׃
בְּעֶצֶם הַיּוֹם הַזֶּה בָּא נֹחַ וְשֵׁם־וְחָם וָיֶפֶת בְּנֵי־נֹחַ וְאֵשֶׁת נֹחַ וּשְׁלֹשֶׁת נְשֵׁי־בָנָיו אִתָּם אֶל־הַתֵּבָה׃
הֵמָּה וְכָל־הַחַיָּה לְמִינָהּ וְכָל־הַבְּהֵמָה לְמִינָהּ וְכָל־הָרֶמֶשׂ הָרֹמֵשׂ עַל־הָאָרֶץ לְמִינֵהוּ וְכָל־הָעוֹף לְמִינֵהוּ כֹּל צִפּוֹר כָּל־כָּנָף׃
וַיָּבֹאוּ אֶל־נֹחַ אֶל־הַתֵּבָה שְׁנַיִם שְׁנַיִם מִכָּל־הַבָּשָׂר אֲשֶׁר־בּוֹ רוּחַ חַיִּים׃
וְהַבָּאִים זָכָר וּנְקֵבָה מִכָּל־בָּשָׂר בָּאוּ כַּאֲשֶׁר צִוָּה אֹתוֹ אֱלֹהִים וַיִּסְגֹּר יְהוָה בַּעֲדוֹ׃
וַיְהִי הַמַּבּוּל אַרְבָּעִים יוֹם עַל־הָאָרֶץ וַיִּרְבּוּ הַמַּיִם וַיִּשְׂאוּ אֶת־הַתֵּבָה וַתָּרָם מֵעַל הָאָרֶץ׃
וַיִּגְבְּרוּ הַמַּיִם וַיִּרְבּוּ מְאֹד עַל־הָאָרֶץ וַתֵּלֶךְ הַתֵּבָה עַל־פְּנֵי הַמָּיִם׃
וְהַמַּיִם גָּבְרוּ מְאֹד מְאֹד עַל־הָאָרֶץ וַיְכֻסּוּ כָּל־הֶהָרִים הַגְּבֹהִים אֲשֶׁר־תַּחַת כָּל־הַשָּׁמָיִם׃
חֲמֵשׁ עֶשְׂרֵה אַמָּה מִלְמַעְלָה גָּבְרוּ הַמָּיִם וַיְכֻסּוּ הֶהָרִים׃
וַיִּגְוַע כָּל־בָּשָׂר הָרֹמֵשׂ עַל־הָאָרֶץ בָּעוֹף וּבַבְּהֵמָה וּבַחַיָּה וּבְכָל־הַשֶּׁרֶץ הַשֹּׁרֵץ עַל־הָאָרֶץ וְכֹל הָאָדָם׃
כֹּל אֲשֶׁר נִשְׁמַת־רוּחַ חַיִּים בְּאַפָּיו מִכֹּל אֲשֶׁר בֶּחָרָבָה מֵתוּ׃
וַיִּמַח אֶת־כָּל־הַיְקוּם אֲשֶׁר עַל־פְּנֵי הָאֲדָמָה מֵאָדָם עַד־בְּהֵמָה עַד־רֶמֶשׂ וְעַד־עוֹף הַשָּׁמַיִם וַיִּמָּחוּ מִן־הָאָרֶץ וַיִשָּׁאֶר אַךְ־נֹחַ וַאֲשֶׁר אִתּוֹ בַּתֵּבָה׃
וַיִּגְבְּרוּ הַמַּיִם עַל־הָאָרֶץ חֲמִשִּׁים וּמְאַת יוֹם׃

Chapter 8

וַיִּזְכֹּר אֱלֹהִים אֶת־נֹחַ וְאֵת כָּל־הַחַיָּה וְאֶת־כָּל־הַבְּהֵמָה אֲשֶׁר אִתּוֹ בַּתֵּבָה וַיַּעֲבֵר אֱלֹהִים רוּחַ עַל־הָאָרֶץ וַיָּשֹׁכּוּ הַמָּיִם׃
וַיִּסָּכְרוּ מַעְיְנֹת תְּהוֹם וַאֲרֻבֹּת הַשָּׁמָיִם וַיִּכָּלֵא הַגֶּשֶׁם מִן־הַשָּׁמָיִם׃
וַיָּשֻׁבוּ הַמַּיִם מֵעַל הָאָרֶץ הָלוֹךְ וָשׁוֹב וַיַּחְסְרוּ הַמַּיִם מִקְצֵה חֲמִשִּׁים וּמְאַת יוֹם׃
וַתָּנַח הַתֵּבָה בַּחֹדֶשׁ הַשְּׁבִיעִי בְּשִׁבְעָה־עָשָׂר יוֹם לַחֹדֶשׁ עַל הָרֵי אֲרָרָט׃
וְהַמַּיִם הָיוּ הָלוֹךְ וְחָסוֹר עַד הַחֹדֶשׁ הָעֲשִׂירִי בָּעֲשִׂירִי בְּאֶחָד לַחֹדֶשׁ נִרְאוּ רָאשֵׁי הֶהָרִים׃
וַיְהִי מִקֵּץ אַרְבָּעִים יוֹם וַיִּפְתַּח נֹחַ אֶת־חַלּוֹן הַתֵּבָה אֲשֶׁר עָשָׂה׃
וַיְשַׁלַּח אֶת־הָעֹרֵב וַיֵּצֵא יָצוֹא וָשׁוֹב עַד־יְבֹשֶׁת הַמַּיִם מֵעַל הָאָרֶץ׃
וַיְשַׁלַּח אֶת־הַיּוֹנָה מֵאִתּוֹ לִרְאוֹת הֲקַלּוּ הַמַּיִם מֵעַל פְּנֵי הָאֲדָמָה׃
וְלֹא־מָצְאָה הַיּוֹנָה מָנוֹחַ לְכַף־רַגְלָהּ וַתָּשָׁב אֵלָיו אֶל־הַתֵּבָה כִּי־מַיִם עַל־פְּנֵי כָל־הָאָרֶץ וַיִּשְׁלַח יָדוֹ וַיִּקָּחֶהָ וַיָּבֵא אֹתָהּ אֵלָיו אֶל־הַתֵּבָה׃
וַיָּחֶל עוֹד שִׁבְעַת יָמִים אֲחֵרִים וַיֹּסֶף שַׁלַּח אֶת־הַיּוֹנָה מִן־הַתֵּבָה׃
וַתָּבֹא אֵלָיו הַיּוֹנָה לְעֵת עֶרֶב וְהִנֵּה עֲלֵה־זַיִת טָרָף בְּפִיהָ וַיֵּדַע נֹחַ כִּי־קַלּוּ הַמַּיִם מֵעַל הָאָרֶץ׃
וַיִּיָּחֶל עוֹד שִׁבְעַת יָמִים אֲחֵרִים וַיְשַׁלַּח אֶת־הַיּוֹנָה וְלֹא־יָסְפָה שׁוּב־אֵלָיו עוֹד׃
וַיְהִי בְּאַחַת וְשֵׁשׁ־מֵאוֹת שָׁנָה בָּרִאשׁוֹן בְּאֶחָד לַחֹדֶשׁ חָרְבוּ הַמַּיִם מֵעַל הָאָרֶץ וַיָּסַר נֹחַ אֶת־מִכְסֵה הַתֵּבָה וַיַּרְא וְהִנֵּה חָרְבוּ פְּנֵי הָאֲדָמָה׃
וּבַחֹדֶשׁ הַשֵּׁנִי בְּשִׁבְעָה וְעֶשְׂרִים יוֹם לַחֹדֶשׁ יָבְשָׁה הָאָרֶץ׃
וַיְדַבֵּר אֱלֹהִים אֶל־נֹחַ לֵאמֹר׃
צֵא מִן־הַתֵּבָה אַתָּה וְאִשְׁתְּךָ וּבָנֶיךָ וּנְשֵׁי־בָנֶיךָ אִתָּךְ׃
כָּל־הַחַיָּה אֲשֶׁר־אִתְּךָ מִכָּל־בָּשָׂר בָּעוֹף וּבַבְּהֵמָה וּבְכָל־הָרֶמֶשׂ הָרֹמֵשׂ עַל־הָאָרֶץ הוצא [הַיְצֵא] אִתָּךְ וְשָׁרְצוּ בָאָרֶץ וּפָרוּ וְרָבוּ עַל־הָאָרֶץ׃
וַיֵּצֵא־נֹחַ וּבָנָיו וְאִשְׁתּוֹ וּנְשֵׁי־בָנָיו אִתּוֹ׃
כָּל־הַחַיָּה כָּל־הָרֶמֶשׂ וְכָל־הָעוֹף כֹּל רוֹמֵשׂ עַל־הָאָרֶץ לְמִשְׁפְּחֹתֵיהֶם יָצְאוּ מִן־הַתֵּבָה׃
וַיִּבֶן נֹחַ מִזְבֵּחַ לַיהוָה וַיִּקַּח מִכֹּל הַבְּהֵמָה הַטְּהוֹרָה וּמִכֹּל הָעוֹף הַטָּהֹר וַיַּעַל עֹלֹת בַּמִּזְבֵּחַ׃
וַיָּרַח יְהוָה אֶת־רֵיחַ הַנִּיחֹחַ וַיֹּאמֶר יְהוָה אֶל־לִבּוֹ לֹא־אֹסִף לְקַלֵּל עוֹד אֶת־הָאֲדָמָה בַּעֲבוּר הָאָדָם כִּי יֵצֶר לֵב הָאָדָם רַע מִנְּעֻרָיו וְלֹא־אֹסִף עוֹד לְהַכּוֹת אֶת־כָּל־חַי כַּאֲשֶׁר עָשִׂיתִי׃
עֹד כָּל־יְמֵי הָאָרֶץ זֶרַע וְקָצִיר וְקֹר וָחֹם וְקַיִץ וָחֹרֶף וְיוֹם וָלַיְלָה לֹא יִשְׁבֹּתוּ׃

Chapter 9

וַיְבָרֶךְ אֱלֹהִים אֶת־נֹחַ וְאֶת־בָּנָיו וַיֹּאמֶר לָהֶם פְּרוּ וּרְבוּ וּמִלְאוּ אֶת־הָאָרֶץ׃
וּמוֹרַאֲכֶם וְחִתְּכֶם יִהְיֶה עַל כָּל־חַיַּת הָאָרֶץ וְעַל כָּל־עוֹף הַשָּׁמָיִם בְּכֹל אֲשֶׁר תִּרְמֹשׂ הָאֲדָמָה וּבְכָל־דְּגֵי הַיָּם בְּיֶדְכֶם נִתָּנוּ׃
כָּל־רֶמֶשׂ אֲשֶׁר הוּא־חַי לָכֶם יִהְיֶה לְאָכְלָה כְּיֶרֶק עֵשֶׂב נָתַתִּי לָכֶם אֶת־כֹּל׃
אַךְ־בָּשָׂר בְּנַפְשׁוֹ דָמוֹ לֹא תֹאכֵלוּ׃
וְאַךְ אֶת־דִּמְכֶם לְנַפְשֹׁתֵיכֶם אֶדְרֹשׁ מִיַּד כָּל־חַיָּה אֶדְרְשֶׁנּוּ וּמִיַּד הָאָדָם מִיַּד אִישׁ אָחִיו אֶדְרֹשׁ אֶת־נֶפֶשׁ הָאָדָם׃
שֹׁפֵךְ דַּם הָאָדָם בָּאָדָם דָּמוֹ יִשָּׁפֵךְ כִּי בְּצֶלֶם אֱלֹהִים עָשָׂה אֶת־הָאָדָם׃
וְאַתֶּם פְּרוּ וּרְבוּ שִׁרְצוּ בָאָרֶץ וּרְבוּ־בָהּ׃
וַיֹּאמֶר אֱלֹהִים אֶל־נֹחַ וְאֶל־בָּנָיו אִתּוֹ לֵאמֹר׃
וַאֲנִי הִנְנִי מֵקִים אֶת־בְּרִיתִי אִתְּכֶם וְאֶת־זַרְעֲכֶם אַחֲרֵיכֶם׃
וְאֵת כָּל־נֶפֶשׁ הַחַיָּה אֲשֶׁר אִתְּכֶם בָּעוֹף בַּבְּהֵמָה וּבְכָל־חַיַּת הָאָרֶץ אִתְּכֶם מִכֹּל יֹצְאֵי הַתֵּבָה לְכֹל חַיַּת הָאָרֶץ׃
וַהֲקִמֹתִי אֶת־בְּרִיתִי אִתְּכֶם וְלֹא־יִכָּרֵת כָּל־בָּשָׂר עוֹד מִמֵּי הַמַּבּוּל וְלֹא־יִהְיֶה עוֹד מַבּוּל לְשַׁחֵת הָאָרֶץ׃
וַיֹּאמֶר אֱלֹהִים זֹאת אוֹת־הַבְּרִית אֲשֶׁר־אֲנִי נֹתֵן בֵּינִי וּבֵינֵיכֶם וּבֵין כָּל־נֶפֶשׁ חַיָּה אֲשֶׁר אִתְּכֶם לְדֹרֹת עוֹלָם׃
אֶת־קַשְׁתִּי נָתַתִּי בֶּעָנָן וְהָיְתָה לְאוֹת בְּרִית בֵּינִי וּבֵין הָאָרֶץ׃
וְהָיָה בְּעַנְנִי עָנָן עַל־הָאָרֶץ וְנִרְאֲתָה הַקֶּשֶׁת בֶּעָנָן׃
וְזָכַרְתִּי אֶת־בְּרִיתִי אֲשֶׁר בֵּינִי וּבֵינֵיכֶם וּבֵין כָּל־נֶפֶשׁ חַיָּה בְּכָל־בָּשָׂר וְלֹא־יִהְיֶה עוֹד הַמַּיִם לְמַבּוּל לְשַׁחֵת כָּל־בָּשָׂר׃
וְהָיְתָה הַקֶּשֶׁת בֶּעָנָן וּרְאִיתִיהָ לִזְכֹּר בְּרִית עוֹלָם בֵּין אֱלֹהִים וּבֵין כָּל־נֶפֶשׁ חַיָּה בְּכָל־בָּשָׂר אֲשֶׁר עַל־הָאָרֶץ׃
וַיֹּאמֶר אֱלֹהִים אֶל־נֹחַ זֹאת אוֹת־הַבְּרִית אֲשֶׁר הֲקִמֹתִי בֵּינִי וּבֵין כָּל־בָּשָׂר אֲשֶׁר עַל־הָאָרֶץ׃
וַיִּהְיוּ בְנֵי־נֹחַ הַיֹּצְאִים מִן־הַתֵּבָה שֵׁם וְחָם וָיָפֶת וְחָם הוּא אֲבִי כְנָעַן׃
שְׁלֹשָׁה אֵלֶּה בְּנֵי־נֹחַ וּמֵאֵלֶּה נָפְצָה כָל־הָאָרֶץ׃
וַיָּחֶל נֹחַ אִישׁ הָאֲדָמָה וַיִּטַּע כָּרֶם׃
וַיֵּשְׁתְּ מִן־הַיַּיִן וַיִּשְׁכָּר וַיִּתְגַּל בְּתוֹךְ אָהֳלֹה׃
וַיַּרְא חָם אֲבִי כְנַעַן אֵת עֶרְוַת אָבִיו וַיַּגֵּד לִשְׁנֵי־אֶחָיו בַּחוּץ׃
וַיִּקַּח שֵׁם וָיֶפֶת אֶת־הַשִּׂמְלָה וַיָּשִׂימוּ עַל־שְׁכֶם שְׁנֵיהֶם וַיֵּלְכוּ אֲחֹרַנִּית וַיְכַסּוּ אֵת עֶרְוַת אֲבִיהֶם וּפְנֵיהֶם אֲחֹרַנִּית וְעֶרְוַת אֲבִיהֶם לֹא רָאוּ׃
וַיִּיקֶץ נֹחַ מִיֵּינוֹ וַיֵּדַע אֵת אֲשֶׁר־עָשָׂה־לוֹ בְּנוֹ הַקָּטָן׃
וַיֹּאמֶר אָרוּר כְּנָעַן עֶבֶד עֲבָדִים יִהְיֶה לְאֶחָיו׃
וַיֹּאמֶר בָּרוּךְ יְהֹוָה אֱלֹהֵי שֵׁם וִיהִי כְנַעַן עֶבֶד לָמוֹ׃
יַפְתְּ אֱלֹהִים לְיֶפֶת וְיִשְׁכֹּן בְּאָהֳלֵי־שֵׁם וִיהִי כְנַעַן עֶבֶד לָמוֹ׃
וַיְחִי־נֹחַ אַחַר הַמַּבּוּל שְׁלֹשׁ מֵאוֹת שָׁנָה וַחֲמִשִּׁים שָׁנָה׃
וַיִּהְיוּ כָּל־יְמֵי־נֹחַ תְּשַׁע מֵאוֹת שָׁנָה וַחֲמִשִּׁים שָׁנָה וַיָּמֹת׃

Chapter 10

וְאֵלֶּה תּוֹלְדֹת בְּנֵי־נֹחַ שֵׁם חָם וָיָפֶת וַיִּוָּלְדוּ לָהֶם בָּנִים אַחַר הַמַּבּוּל׃
בְּנֵי יֶפֶת גֹּמֶר וּמָגוֹג וּמָדַי וְיָוָן וְתֻבָל וּמֶשֶׁךְ וְתִירָס׃
וּבְנֵי גֹּמֶר אַשְׁכֲּנַז וְרִיפַת וְתֹגַרְמָה׃
וּבְנֵי יָוָן אֱלִישָׁה וְתַרְשִׁישׁ כִּתִּים וְדֹדָנִים׃
מֵאֵלֶּה נִפְרְדוּ אִיֵּי הַגּוֹיִם בְּאַרְצֹתָם אִישׁ לִלְשֹׁנוֹ לְמִשְׁפְּחֹתָם בְּגוֹיֵהֶם׃
וּבְנֵי חָם כּוּשׁ וּמִצְרַיִם וּפוּט וּכְנָעַן׃
וּבְנֵי כוּשׁ סְבָא וַחֲוִילָה וְסַבְתָּה וְרַעְמָה וְסַבְתְּכָא וּבְנֵי רַעְמָה שְׁבָא וּדְדָן׃
וְכוּשׁ יָלַד אֶת־נִמְרֹד הוּא הֵחֵל לִהְיוֹת גִּבֹּר בָּאָרֶץ׃
הוּא־הָיָה גִבֹּר־צַיִד לִפְנֵי יְהוָה עַל־כֵּן יֵאָמַר כְּנִמְרֹד גִּבּוֹר צַיִד לִפְנֵי יְהוָה׃
וַתְּהִי רֵאשִׁית מַמְלַכְתּוֹ בָּבֶל וְאֶרֶךְ וְאַכַּד וְכַלְנֵה בְּאֶרֶץ שִׁנְעָר׃
מִן־הָאָרֶץ הַהִוא יָצָא אַשּׁוּר וַיִּבֶן אֶת־נִינְוֵה וְאֶת־רְחֹבֹת עִיר וְאֶת־כָּלַח׃
וְאֶת־רֶסֶן בֵּין נִינְוֵה וּבֵין כָּלַח הִוא הָעִיר הַגְּדֹלָה׃
וּמִצְרַיִם יָלַד אֶת־לוּדִים וְאֶת־עֲנָמִים וְאֶת־לְהָבִים וְאֶת־נַפְתֻּחִים׃
וְאֶת־פַּתְרֻסִים וְאֶת־כַּסְלֻחִים אֲשֶׁר יָצְאוּ מִשָּׁם פְּלִשְׁתִּים וְאֶת־כַּפְתֹּרִים׃
וּכְנַעַן יָלַד אֶת־צִידֹן בְּכֹרוֹ וְאֶת־חֵת׃
וְאֶת־הַיְבוּסִי וְאֶת־הָאֱמֹרִי וְאֵת הַגִּרְגָּשִׁי׃
וְאֶת־הַחִוִּי וְאֶת־הַעַרְקִי וְאֶת־הַסִּינִי׃
וְאֶת־הָאַרְוָדִי וְאֶת־הַצְּמָרִי וְאֶת־הַחֲמָתִי וְאַחַר נָפֹצוּ מִשְׁפְּחוֹת הַכְּנַעֲנִי׃
וַיְהִי גְּבוּל הַכְּנַעֲנִי מִצִּידֹן בֹּאֲכָה גְרָרָה עַד־עַזָּה בֹּאֲכָה סְדֹמָה וַעֲמֹרָה וְאַדְמָה וּצְבֹיִם עַד־לָשַׁע׃
אֵלֶּה בְנֵי־חָם לְמִשְׁפְּחֹתָם לִלְשֹׁנֹתָם בְּאַרְצֹתָם בְּגוֹיֵהֶם׃
וּלְשֵׁם יֻלַּד גַּם־הוּא אֲבִי כָּל־בְּנֵי־עֵבֶר אֲחִי יֶפֶת הַגָּדוֹל׃
בְּנֵי שֵׁם עֵילָם וְאַשּׁוּר וְאַרְפַּכְשַׁד וְלוּד וַאֲרָם׃
וּבְנֵי אֲרָם עוּץ וְחוּל וְגֶתֶר וָמַשׁ׃
וְאַרְפַּכְשַׁד יָלַד אֶת־שָׁלַח וְשֶׁלַח יָלַד אֶת־עֵבֶר׃
וּלְעֵבֶר יֻלַּד שְׁנֵי בָנִים שֵׁם הָאֶחָד פֶּלֶג כִּי בְיָמָיו נִפְלְגָה הָאָרֶץ וְשֵׁם אָחִיו יָקְטָן׃
וְיָקְטָן יָלַד אֶת־אַלְמוֹדָד וְאֶת־שָׁלֶף וְאֶת־חֲצַרְמָוֶת וְאֶת־יָרַח׃
וְאֶת־הֲדוֹרָם וְאֶת־אוּזָל וְאֶת־דִּקְלָה׃
וְאֶת־עוֹבָל וְאֶת־אֲבִימָאֵל וְאֶת־שְׁבָא׃
וְאֶת־אוֹפִר וְאֶת־חֲוִילָה וְאֶת־יוֹבָב כָּל־אֵלֶּה בְּנֵי יָקְטָן׃
וַיְהִי מוֹשָׁבָם מִמֵּשָׁא בֹּאֲכָה סְפָרָה הַר הַקֶּדֶם׃
אֵלֶּה בְנֵי־שֵׁם לְמִשְׁפְּחֹתָם לִלְשֹׁנֹתָם בְּאַרְצֹתָם לְגוֹיֵהֶם׃
אֵלֶּה מִשְׁפְּחֹת בְּנֵי־נֹחַ לְתוֹלְדֹתָם בְּגוֹיֵהֶם וּמֵאֵלֶּה נִפְרְדוּ הַגּוֹיִם בָּאָרֶץ אַחַר הַמַּבּוּל׃

Chapter 11

וַיְהִי כָל־הָאָרֶץ שָׂפָה אֶחָת וּדְבָרִים אֲחָדִים׃
וַיְהִי בְּנָסְעָם מִקֶּדֶם וַיִּמְצְאוּ בִקְעָה בְּאֶרֶץ שִׁנְעָר וַיֵּשְׁבוּ שָׁם׃
וַיֹּאמְרוּ אִישׁ אֶל־רֵעֵהוּ הָבָה נִלְבְּנָה לְבֵנִים וְנִשְׂרְפָה לִשְׂרֵפָה וַתְּהִי לָהֶם הַלְּבֵנָה לְאָבֶן וְהַחֵמָר הָיָה לָהֶם לַחֹמֶר׃
וַיֹּאמְרוּ הָבָה נִבְנֶה־לָּנוּ עִיר וּמִגְדָּל וְרֹאשׁוֹ בַשָּׁמַיִם וְנַעֲשֶׂה־לָּנוּ שֵׁם פֶּן־נָפוּץ עַל־פְּנֵי כָל־הָאָרֶץ׃
וַיֵּרֶד יְהוָה לִרְאֹת אֶת־הָעִיר וְאֶת־הַמִּגְדָּל אֲשֶׁר בָּנוּ בְּנֵי הָאָדָם׃
וַיֹּאמֶר יְהוָה הֵן עַם אֶחָד וְשָׂפָה אַחַת לְכֻלָּם וְזֶה הַחִלָּם לַעֲשׂוֹת וְעַתָּה לֹא־יִבָּצֵר מֵהֶם כֹּל אֲשֶׁר יָזְמוּ לַעֲשׂוֹת׃
הָבָה נֵרְדָה וְנָבְלָה שָׁם שְׂפָתָם אֲשֶׁר לֹא יִשְׁמְעוּ אִישׁ שְׂפַת רֵעֵהוּ׃
וַיָּפֶץ יְהוָה אֹתָם מִשָּׁם עַל־פְּנֵי כָל־הָאָרֶץ וַיַּחְדְּלוּ לִבְנֹת הָעִיר׃
עַל־כֵּן קָרָא שְׁמָהּ בָּבֶל כִּי־שָׁם בָּלַל יְהוָה שְׂפַת כָּל־הָאָרֶץ וּמִשָּׁם הֱפִיצָם יְהוָה עַל־פְּנֵי כָּל־הָאָרֶץ׃
אֵלֶּה תּוֹלְדֹת שֵׁם שֵׁם בֶּן־מְאַת שָׁנָה וַיּוֹלֶד אֶת־אַרְפַּכְשָׁד שְׁנָתַיִם אַחַר הַמַּבּוּל׃
וַיְחִי־שֵׁם אַחֲרֵי הוֹלִידוֹ אֶת־אַרְפַּכְשָׁד חֲמֵשׁ מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וְאַרְפַּכְשַׁד חַי חָמֵשׁ וּשְׁלֹשִׁים שָׁנָה וַיּוֹלֶד אֶת־שָׁלַח׃
וַיְחִי אַרְפַּכְשַׁד אַחֲרֵי הוֹלִידוֹ אֶת־שֶׁלַח שָׁלֹשׁ שָׁנִים וְאַרְבַּע מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וְשֶׁלַח חַי שְׁלֹשִׁים שָׁנָה וַיּוֹלֶד אֶת־עֵבֶר׃
וַיְחִי־שֶׁלַח אַחֲרֵי הוֹלִידוֹ אֶת־עֵבֶר שָׁלֹשׁ שָׁנִים וְאַרְבַּע מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְחִי־עֵבֶר אַרְבַּע וּשְׁלֹשִׁים שָׁנָה וַיּוֹלֶד אֶת־פָּלֶג׃
וַיְחִי־עֵבֶר אַחֲרֵי הוֹלִידוֹ אֶת־פֶּלֶג שְׁלֹשִׁים שָׁנָה וְאַרְבַּע מֵאוֹת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְחִי־פֶלֶג שְׁלֹשִׁים שָׁנָה וַיּוֹלֶד אֶת־רְעוּ׃
וַיְחִי־פֶלֶג אַחֲרֵי הוֹלִידוֹ אֶת־רְעוּ תֵּשַׁע שָׁנִים וּמָאתַיִם שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְחִי רְעוּ שְׁתַּיִם וּשְׁלֹשִׁים שָׁנָה וַיּוֹלֶד אֶת־שְׂרוּג׃
וַיְחִי רְעוּ אַחֲרֵי הוֹלִידוֹ אֶת־שְׂרוּג שֶׁבַע שָׁנִים וּמָאתַיִם שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְחִי שְׂרוּג שְׁלֹשִׁים שָׁנָה וַיּוֹלֶד אֶת־נָחוֹר׃
וַיְחִי שְׂרוּג אַחֲרֵי הוֹלִידוֹ אֶת־נָחוֹר מָאתַיִם שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְחִי נָחוֹר תֵּשַׁע וְעֶשְׂרִים שָׁנָה וַיּוֹלֶד אֶת־תָּרַח׃
וַיְחִי נָחוֹר אַחֲרֵי הוֹלִידוֹ אֶת־תֶּרַח תְּשַׁע־עֶשְׂרֵה שָׁנָה וּמְאַת שָׁנָה וַיּוֹלֶד בָּנִים וּבָנוֹת׃
וַיְחִי־תֶרַח שִׁבְעִים שָׁנָה וַיּוֹלֶד אֶת־אַבְרָם אֶת־נָחוֹר וְאֶת־הָרָן׃
וְאֵלֶּה תּוֹלְדֹת תֶּרַח תֶּרַח הוֹלִיד אֶת־אַבְרָם אֶת־נָחוֹר וְאֶת־הָרָן וְהָרָן הוֹלִיד אֶת־לוֹט׃
וַיָּמָת הָרָן עַל־פְּנֵי תֶּרַח אָבִיו בְּאֶרֶץ מוֹלַדְתּוֹ בְּאוּר כַּשְׂדִּים׃
וַיִּקַּח אַבְרָם וְנָחוֹר לָהֶם נָשִׁים שֵׁם אֵשֶׁת־אַבְרָם שָׂרָי וְשֵׁם אֵשֶׁת־נָחוֹר מִלְכָּה בַּת־הָרָן אֲבִי־מִלְכָּה וַאֲבִי יִסְכָּה׃
וַתְּהִי שָׂרַי עֲקָרָה אֵין לָהּ וָלָד׃
וַיִּקַּח תֶּרַח אֶת־אַבְרָם בְּנוֹ וְאֶת־לוֹט בֶּן־הָרָן בֶּן־בְּנוֹ וְאֵת שָׂרַי כַּלָּתוֹ אֵשֶׁת אַבְרָם בְּנוֹ וַיֵּצְאוּ אִתָּם מֵאוּר כַּשְׂדִּים לָלֶכֶת אַרְצָה כְּנַעַן וַיָּבֹאוּ עַד־חָרָן וַיֵּשְׁבוּ שָׁם׃
וַיִּהְיוּ יְמֵי־תֶרַח חָמֵשׁ שָׁנִים וּמָאתַיִם שָׁנָה וַיָּמָת תֶּרַח בְּחָרָן׃

Chapter 12

וַיֹּאמֶר יְהוָה אֶל־אַבְרָם לֶךְ־לְךָ מֵאַרְצְךָ וּמִמּוֹלַדְתְּךָ וּמִבֵּית אָבִיךָ אֶל־הָאָרֶץ אֲשֶׁר אַרְאֶךָּ׃
וְאֶעֶשְׂךָ לְגוֹי גָּדוֹל וַאֲבָרֶכְךָ וַאֲגַדְּלָה שְׁמֶךָ וֶהְיֵה בְּרָכָה׃
וַאֲבָרֲכָה מְבָרְכֶיךָ וּמְקַלֶּלְךָ אָאֹר וְנִבְרְכוּ בְךָ כֹּל מִשְׁפְּחֹת הָאֲדָמָה׃
וַיֵּלֶךְ אַבְרָם כַּאֲשֶׁר דִּבֶּר אֵלָיו יְהוָה וַיֵּלֶךְ אִתּוֹ לוֹט וְאַבְרָם בֶּן־חָמֵשׁ שָׁנִים וְשִׁבְעִים שָׁנָה בְּצֵאתוֹ מֵחָרָן׃
וַיִּקַּח אַבְרָם אֶת־שָׂרַי אִשְׁתּוֹ וְאֶת־לוֹט בֶּן־אָחִיו וְאֶת־כָּל־רְכוּשָׁם אֲשֶׁר רָכָשׁוּ וְאֶת־הַנֶּפֶשׁ אֲשֶׁר־עָשׂוּ בְחָרָן וַיֵּצְאוּ לָלֶכֶת אַרְצָה כְּנַעַן וַיָּבֹאוּ אַרְצָה כְּנָעַן׃
וַיַּעֲבֹר אַבְרָם בָּאָרֶץ עַד מְקוֹם שְׁכֶם עַד אֵלוֹן מוֹרֶה וְהַכְּנַעֲנִי אָז בָּאָרֶץ׃
וַיֵּרָא יְהוָה אֶל־אַבְרָם וַיֹּאמֶר לְזַרְעֲךָ אֶתֵּן אֶת־הָאָרֶץ הַזֹּאת וַיִּבֶן שָׁם מִזְבֵּחַ לַיהוָה הַנִּרְאֶה אֵלָיו׃
וַיַּעְתֵּק מִשָּׁם הָהָרָה מִקֶּדֶם לְבֵית־אֵל וַיֵּט אָהֳלֹה בֵּית־אֵל מִיָּם וְהָעַי מִקֶּדֶם וַיִּבֶן־שָׁם מִזְבֵּחַ לַיהוָה וַיִּקְרָא בְּשֵׁם יְהוָה׃
וַיִּסַּע אַבְרָם הָלוֹךְ וְנָסוֹעַ הַנֶּגְבָּה׃
וַיְהִי רָעָב בָּאָרֶץ וַיֵּרֶד אַבְרָם מִצְרַיְמָה לָגוּר שָׁם כִּי־כָבֵד הָרָעָב בָּאָרֶץ׃
וַיְהִי כַּאֲשֶׁר הִקְרִיב לָבוֹא מִצְרָיְמָה וַיֹּאמֶר אֶל־שָׂרַי אִשְׁתּוֹ הִנֵּה־נָא יָדַעְתִּי כִּי אִשָּׁה יְפַת־מַרְאֶה אָתְּ׃
וְהָיָה כִּי־יִרְאוּ אֹתָךְ הַמִּצְרִים וְאָמְרוּ אִשְׁתּוֹ זֹאת וְהָרְגוּ אֹתִי וְאֹתָךְ יְחַיּוּ׃
אִמְרִי־נָא אֲחֹתִי אָתְּ לְמַעַן יִיטַב־לִי בַעֲבוּרֵךְ וְחָיְתָה נַפְשִׁי בִּגְלָלֵךְ׃
וַיְהִי כְּבוֹא אַבְרָם מִצְרָיְמָה וַיִּרְאוּ הַמִּצְרִים אֶת־הָאִשָּׁה כִּי־יָפָה הִוא מְאֹד׃
וַיִּרְאוּ אֹתָהּ שָׂרֵי פַרְעֹה וַיְהַלְלוּ אֹתָהּ אֶל־פַּרְעֹה וַתֻּקַּח הָאִשָּׁה בֵּית פַּרְעֹה׃
וּלְאַבְרָם הֵיטִיב בַּעֲבוּרָהּ וַיְהִי־לוֹ צֹאן־וּבָקָר וַחֲמֹרִים וַעֲבָדִים וּשְׁפָחֹת וַאֲתֹנֹת וּגְמַלִּים׃
וַיְנַגַּע יְהוָה אֶת־פַּרְעֹה נְגָעִים גְּדֹלִים וְאֶת־בֵּיתוֹ עַל־דְּבַר שָׂרַי אֵשֶׁת אַבְרָם׃
וַיִּקְרָא פַרְעֹה לְאַבְרָם וַיֹּאמֶר מַה־זֹּאת עָשִׂיתָ לִּי לָמָּה לֹא־הִגַּדְתָּ לִּי כִּי אִשְׁתְּךָ הִוא׃
לָמָה אָמַרְתָּ אֲחֹתִי הִוא וָאֶקַּח אֹתָהּ לִי לְאִשָּׁה וְעַתָּה הִנֵּה אִשְׁתְּךָ קַח וָלֵךְ׃
וַיְצַו עָלָיו פַּרְעֹה אֲנָשִׁים וַיְשַׁלְּחוּ אֹתוֹ וְאֶת־אִשְׁתּוֹ וְאֶת־כָּל־אֲשֶׁר־לוֹ׃

Chapter 13

וַיַּעַל אַבְרָם מִמִּצְרַיִם הוּא וְאִשְׁתּוֹ וְכָל־אֲשֶׁר־לוֹ וְלוֹט עִמּוֹ הַנֶּגְבָּה׃
וְאַבְרָם כָּבֵד מְאֹד בַּמִּקְנֶה בַּכֶּסֶף וּבַזָּהָב׃
וַיֵּלֶךְ לְמַסָּעָיו מִנֶּגֶב וְעַד־בֵּית־אֵל עַד־הַמָּקוֹם אֲשֶׁר־הָיָה שָׁם אהלה [אָהֳלוֹ] בַּתְּחִלָּה בֵּין בֵּית־אֵל וּבֵין הָעָי׃
אֶל־מְקוֹם הַמִּזְבֵּחַ אֲשֶׁר־עָשָׂה שָׁם בָּרִאשֹׁנָה וַיִּקְרָא שָׁם אַבְרָם בְּשֵׁם יְהוָה׃
וְגַם־לְלוֹט הַהֹלֵךְ אֶת־אַבְרָם הָיָה צֹאן־וּבָקָר וְאֹהָלִים׃
וְלֹא־נָשָׂא אֹתָם הָאָרֶץ לָשֶׁבֶת יַחְדָּו כִּי־הָיָה רְכוּשָׁם רָב וְלֹא יָכְלוּ לָשֶׁבֶת יַחְדָּו׃
וַיְהִי־רִיב בֵּין רֹעֵי מִקְנֵה־אַבְרָם וּבֵין רֹעֵי מִקְנֵה־לוֹט וְהַכְּנַעֲנִי וְהַפְּרִזִּי אָז יֹשֵׁב בָּאָרֶץ׃
וַיֹּאמֶר אַבְרָם אֶל־לוֹט אַל־נָא תְהִי מְרִיבָה בֵּינִי וּבֵינֶיךָ וּבֵין רֹעַי וּבֵין רֹעֶיךָ כִּי־אֲנָשִׁים אַחִים אֲנָחְנוּ׃
הֲלֹא כָל־הָאָרֶץ לְפָנֶיךָ הִפָּרֶד נָא מֵעָלָי אִם־הַשְּׂמֹאל וְאֵימִנָה וְאִם־הַיָּמִין וְאַשְׂמְאִילָה׃
וַיִּשָּׂא־לוֹט אֶת־עֵינָיו וַיַּרְא אֶת־כָּל־כִּכַּר הַיַּרְדֵּן כִּי כֻלָּהּ מַשְׁקֶה לִפְנֵי שַׁחֵת יְהוָה אֶת־סְדֹם וְאֶת־עֲמֹרָה כְּגַן־יְהוָה כְּאֶרֶץ מִצְרַיִם בֹּאֲכָה צֹעַר׃
וַיִּבְחַר־לוֹ לוֹט אֵת כָּל־כִּכַּר הַיַּרְדֵּן וַיִּסַּע לוֹט מִקֶּדֶם וַיִּפָּרְדוּ אִישׁ מֵעַל אָחִיו׃
אַבְרָם יָשַׁב בְּאֶרֶץ־כְּנָעַן וְלוֹט יָשַׁב בְּעָרֵי הַכִּכָּר וַיֶּאֱהַל עַד־סְדֹם׃
וְאַנְשֵׁי סְדֹם רָעִים וְחַטָּאִים לַיהוָה מְאֹד׃
וַיהוָה אָמַר אֶל־אַבְרָם אַחֲרֵי הִפָּרֶד־לוֹט מֵעִמּוֹ שָׂא נָא עֵינֶיךָ וּרְאֵה מִן־הַמָּקוֹם אֲשֶׁר־אַתָּה שָׁם צָפֹנָה וָנֶגְבָּה וָקֵדְמָה וָיָמָּה׃
כִּי אֶת־כָּל־הָאָרֶץ אֲשֶׁר־אַתָּה רֹאֶה לְךָ אֶתְּנֶנָּה וּלְזַרְעֲךָ עַד־עוֹלָם׃
וְשַׂמְתִּי אֶת־זַרְעֲךָ כַּעֲפַר הָאָרֶץ אֲשֶׁר אִם־יוּכַל אִישׁ לִמְנוֹת אֶת־עֲפַר הָאָרֶץ גַּם־זַרְעֲךָ יִמָּנֶה׃
קוּם הִתְהַלֵּךְ בָּאָרֶץ לְאָרְכָּהּ וּלְרָחְבָּהּ כִּי לְךָ אֶתְּנֶנָּה׃
וַיֶּאֱהַל אַבְרָם וַיָּבֹא וַיֵּשֶׁב בְּאֵלֹנֵי מַמְרֵא אֲשֶׁר בְּחֶבְרוֹן וַיִּבֶן־שָׁם מִזְבֵּחַ לַיהוָה׃

Chapter 14

וַיְהִי בִּימֵי אַמְרָפֶל מֶלֶךְ־שִׁנְעָר אַרְיוֹךְ מֶלֶךְ אֶלָּסָר כְּדָרְלָעֹמֶר מֶלֶךְ עֵילָם וְתִדְעָל מֶלֶךְ גּוֹיִם׃
עָשׂוּ מִלְחָמָה אֶת־בֶּרַע מֶלֶךְ סְדֹם וְאֶת־בִּרְשַׁע מֶלֶךְ עֲמֹרָה שִׁנְאָב מֶלֶךְ אַדְמָה וְשֶׁמְאֵבֶר מֶלֶךְ צביים [צְבוֹיִים] וּמֶלֶךְ בֶּלַע הִיא־צֹעַר׃
כָּל־אֵלֶּה חָבְרוּ אֶל־עֵמֶק הַשִּׂדִּים הוּא יָם הַמֶּלַח׃
שְׁתֵּים עֶשְׂרֵה שָׁנָה עָבְדוּ אֶת־כְּדָרְלָעֹמֶר וּשְׁלֹשׁ־עֶשְׂרֵה שָׁנָה מָרָדוּ׃
וּבְאַרְבַּע עֶשְׂרֵה שָׁנָה בָּא כְדָרְלָעֹמֶר וְהַמְּלָכִים אֲשֶׁר אִתּוֹ וַיַּכּוּ אֶת־רְפָאִים בְּעַשְׁתְּרֹת קַרְנַיִם וְאֶת־הַזּוּזִים בְּהָם וְאֵת הָאֵימִים בְּשָׁוֵה קִרְיָתָיִם׃
וְאֶת־הַחֹרִי בְּהַרְרָם שֵׂעִיר עַד אֵיל פָּארָן אֲשֶׁר עַל־הַמִּדְבָּר׃
וַיָּשֻׁבוּ וַיָּבֹאוּ אֶל־עֵין מִשְׁפָּט הִוא קָדֵשׁ וַיַּכּוּ אֶת־כָּל־שְׂדֵה הָעֲמָלֵקִי וְגַם אֶת־הָאֱמֹרִי הַיֹּשֵׁב בְּחַצְצֹן תָּמָר׃
וַיֵּצֵא מֶלֶךְ־סְדֹם וּמֶלֶךְ עֲמֹרָה וּמֶלֶךְ אַדְמָה וּמֶלֶךְ צביים [צְבוֹיִם] וּמֶלֶךְ בֶּלַע הִוא־צֹעַר וַיַּעַרְכוּ אִתָּם מִלְחָמָה בְּעֵמֶק הַשִּׂדִּים׃
אֵת כְּדָרְלָעֹמֶר מֶלֶךְ עֵילָם וְתִדְעָל מֶלֶךְ גּוֹיִם וְאַמְרָפֶל מֶלֶךְ שִׁנְעָר וְאַרְיוֹךְ מֶלֶךְ אֶלָּסָר אַרְבָּעָה מְלָכִים אֶת־הַחֲמִשָּׁה׃
וְעֵמֶק הַשִׂדִּים בֶּאֱרֹת בֶּאֱרֹת חֵמָר וַיָּנֻסוּ מֶלֶךְ־סְדֹם וַעֲמֹרָה וַיִּפְּלוּ־שָׁמָּה וְהַנִּשְׁאָרִים הֶרָה נָּסוּ׃
וַיִּקְחוּ אֶת־כָּל־רְכֻשׁ סְדֹם וַעֲמֹרָה וְאֶת־כָּל־אָכְלָם וַיֵּלֵכוּ׃
וַיִּקְחוּ אֶת־לוֹט וְאֶת־רְכֻשׁוֹ בֶּן־אֲחִי אַבְרָם וַיֵּלֵכוּ וְהוּא יֹשֵׁב בִּסְדֹם׃
וַיָּבֹא הַפָּלִיט וַיַּגֵּד לְאַבְרָם הָעִבְרִי וְהוּא שֹׁכֵן בְּאֵלֹנֵי מַמְרֵא הָאֱמֹרִי אֲחִי אֶשְׁכֹּל וַאֲחִי עָנֵר וְהֵם בַּעֲלֵי בְרִית־אַבְרָם׃
וַיִּשְׁמַע אַבְרָם כִּי נִשְׁבָּה אָחִיו וַיָּרֶק אֶת־חֲנִיכָיו יְלִידֵי בֵיתוֹ שְׁמֹנָה עָשָׂר וּשְׁלֹשׁ מֵאוֹת וַיִּרְדֹּף עַד־דָּן׃
וַיֵּחָלֵק עֲלֵיהֶם לַיְלָה הוּא וַעֲבָדָיו וַיַּכֵּם וַיִּרְדְּפֵם עַד־חוֹבָה אֲשֶׁר מִשְּׂמֹאל לְדַמָּשֶׂק׃
וַיָּשֶׁב אֵת כָּל־הָרְכֻשׁ וְגַם אֶת־לוֹט אָחִיו וּרְכֻשׁוֹ הֵשִׁיב וְגַם אֶת־הַנָּשִׁים וְאֶת־הָעָם׃
וַיֵּצֵא מֶלֶךְ־סְדֹם לִקְרָאתוֹ אַחֲרֵי שׁוּבוֹ מֵהַכּוֹת אֶת־כְּדָרלָעֹמֶר וְאֶת־הַמְּלָכִים אֲשֶׁר אִתּוֹ אֶל־עֵמֶק שָׁוֵה הוּא עֵמֶק הַמֶּלֶךְ׃
וּמַלְכִּי־צֶדֶק מֶלֶךְ שָׁלֵם הוֹצִיא לֶחֶם וָיָיִן וְהוּא כֹהֵן לְאֵל עֶלְיוֹן׃
וַיְבָרְכֵהוּ וַיֹּאמַר בָּרוּךְ אַבְרָם לְאֵל עֶלְיוֹן קֹנֵה שָׁמַיִם וָאָרֶץ׃
וּבָרוּךְ אֵל עֶלְיוֹן אֲשֶׁר־מִגֵּן צָרֶיךָ בְּיָדֶךָ וַיִּתֶּן־לוֹ מַעֲשֵׂר מִכֹּל׃
וַיֹּאמֶר מֶלֶךְ־סְדֹם אֶל־אַבְרָם תֶּן־לִי הַנֶּפֶשׁ וְהָרְכֻשׁ קַח־לָךְ׃
וַיֹּאמֶר אַבְרָם אֶל־מֶלֶךְ סְדֹם הֲרִימֹתִי יָדִי אֶל־יְהוָה אֵל עֶלְיוֹן קֹנֵה שָׁמַיִם וָאָרֶץ׃
אִם־מִחוּט וְעַד שְׂרוֹךְ־נַעַל וְאִם־אֶקַּח מִכָּל־אֲשֶׁר־לָךְ וְלֹא תֹאמַר אֲנִי הֶעֱשַׁרְתִּי אֶת־אַבְרָם׃
בִּלְעָדַי רַק אֲשֶׁר אָכְלוּ הַנְּעָרִים וְחֵלֶק הָאֲנָשִׁים אֲשֶׁר הָלְכוּ אִתִּי עָנֵר אֶשְׁכֹּל וּמַמְרֵא הֵם יִקְחוּ חֶלְקָם׃

Chapter 15

אַחַר הַדְּבָרִים הָאֵלֶּה הָיָה דְבַר־יְהוָה אֶל־אַבְרָם בַּמַּחֲזֶה לֵאמֹר אַל־תִּירָא אַבְרָם אָנֹכִי מָגֵן לָךְ שְׂכָרְךָ הַרְבֵּה מְאֹד׃
וַיֹּאמֶר אַבְרָם אֲדֹנָי יֱהוִה מַה־תִּתֶּן־לִי וְאָנֹכִי הוֹלֵךְ עֲרִירִי וּבֶן־מֶשֶׁק בֵּיתִי הוּא דַּמֶּשֶׂק אֱלִיעֶזֶר׃
וַיֹּאמֶר אַבְרָם הֵן לִי לֹא נָתַתָּה זָרַע וְהִנֵּה בֶן־בֵּיתִי יוֹרֵשׁ אֹתִי׃
וְהִנֵּה דְבַר־יְהוָה אֵלָיו לֵאמֹר לֹא יִירָשְׁךָ זֶה כִּי־אִם אֲשֶׁר יֵצֵא מִמֵּעֶיךָ הוּא יִירָשֶׁךָ׃
וַיּוֹצֵא אֹתוֹ הַחוּצָה וַיֹּאמֶר הַבֶּט־נָא הַשָּׁמַיְמָה וּסְפֹר הַכּוֹכָבִים אִם־תּוּכַל לִסְפֹּר אֹתָם וַיֹּאמֶר לוֹ כֹּה יִהְיֶה זַרְעֶךָ׃
וְהֶאֱמִן בַּיהוָה וַיַּחְשְׁבֶהָ לּוֹ צְדָקָה׃
וַיֹּאמֶר אֵלָיו אֲנִי יְהוָה אֲשֶׁר הוֹצֵאתִיךָ מֵאוּר כַּשְׂדִּים לָתֶת לְךָ אֶת־הָאָרֶץ הַזֹּאת לְרִשְׁתָּהּ׃
וַיֹּאמַר אֲדֹנָי יֱהוִה בַּמָּה אֵדַע כִּי אִירָשֶׁנָּה׃
וַיֹּאמֶר אֵלָיו קְחָה לִי עֶגְלָה מְשֻׁלֶּשֶׁת וְעֵז מְשֻׁלֶּשֶׁת וְאַיִל מְשֻׁלָּשׁ וְתֹר וְגוֹזָל׃
וַיִּקַּח־לוֹ אֶת־כָּל־אֵלֶּה וַיְבַתֵּר אֹתָם בַּתָּוֶךְ וַיִּתֵּן אִישׁ־בִּתְרוֹ לִקְרַאת רֵעֵהוּ וְאֶת־הַצִפֹּר לֹא בָתָר׃
וַיֵּרֶד הָעַיִט עַל־הַפְּגָרִים וַיַּשֵּׁב אֹתָם אַבְרָם׃
וַיְהִי הַשֶּׁמֶשׁ לָבוֹא וְתַרְדֵּמָה נָפְלָה עַל־אַבְרָם וְהִנֵּה אֵימָה חֲשֵׁכָה גְדֹלָה נֹפֶלֶת עָלָיו׃
וַיֹּאמֶר לְאַבְרָם יָדֹעַ תֵּדַע כִּי־גֵר יִהְיֶה זַרְעֲךָ בְּאֶרֶץ לֹא לָהֶם וַעֲבָדוּם וְעִנּוּ אֹתָם אַרְבַּע מֵאוֹת שָׁנָה׃
וְגַם אֶת־הַגּוֹי אֲשֶׁר יַעֲבֹדוּ דָּן אָנֹכִי וְאַחֲרֵי־כֵן יֵצְאוּ בִּרְכֻשׁ גָּדוֹל׃
וְאַתָּה תָּבוֹא אֶל־אֲבֹתֶיךָ בְּשָׁלוֹם תִּקָּבֵר בְּשֵׂיבָה טוֹבָה׃
וְדוֹר רְבִיעִי יָשׁוּבוּ הֵנָּה כִּי לֹא־שָׁלֵם עֲוֺן הָאֱמֹרִי עַד־הֵנָּה׃
וַיְהִי הַשֶּׁמֶשׁ בָּאָה וַעֲלָטָה הָיָה וְהִנֵּה תַנּוּר עָשָׁן וְלַפִּיד אֵשׁ אֲשֶׁר עָבַר בֵּין הַגְּזָרִים הָאֵלֶּה׃
בַּיּוֹם הַהוּא כָּרַת יְהוָה אֶת־אַבְרָם בְּרִית לֵאמֹר לְזַרְעֲךָ נָתַתִּי אֶת־הָאָרֶץ הַזֹּאת מִנְּהַר מִצְרַיִם עַד־הַנָּהָר הַגָּדֹל נְהַר־פְּרָת׃
אֶת־הַקֵּינִי וְאֶת־הַקְּנִזִּי וְאֵת הַקַּדְמֹנִי׃
וְאֶת־הַחִתִּי וְאֶת־הַפְּרִזִּי וְאֶת־הָרְפָאִים׃
וְאֶת־הָאֱמֹרִי וְאֶת־הַכְּנַעֲנִי וְאֶת־הַגִּרְגָּשִׁי וְאֶת־הַיְבוּסִי׃

Chapter 16

וְשָׂרַי אֵשֶׁת אַבְרָם לֹא יָלְדָה לוֹ וְלָהּ שִׁפְחָה מִצְרִית וּשְׁמָהּ הָגָר׃
וַתֹּאמֶר שָׂרַי אֶל־אַבְרָם הִנֵּה־נָא עֲצָרַנִי יְהוָה מִלֶּדֶת בֹּא־נָא אֶל־שִׁפְחָתִי אוּלַי אִבָּנֶה מִמֶּנָּה וַיִּשְׁמַע אַבְרָם לְקוֹל שָׂרָי׃
וַתִּקַּח שָׂרַי אֵשֶׁת־אַבְרָם אֶת־הָגָר הַמִּצְרִית שִׁפְחָתָהּ מִקֵּץ עֶשֶׂר שָׁנִים לְשֶׁבֶת אַבְרָם בְּאֶרֶץ כְּנָעַן וַתִּתֵּן אֹתָהּ לְאַבְרָם אִישָׁהּ לוֹ לְאִשָּׁה׃
וַיָּבֹא אֶל־הָגָר וַתַּהַר וַתֵּרֶא כִּי הָרָתָה וַתֵּקַל גְּבִרְתָּהּ בְּעֵינֶיהָ׃
וַתֹּאמֶר שָׂרַי אֶל־אַבְרָם חֲמָסִי עָלֶיךָ אָנֹכִי נָתַתִּי שִׁפְחָתִי בְּחֵיקֶךָ וַתֵּרֶא כִּי הָרָתָה וָאֵקַל בְּעֵינֶיהָ יִשְׁפֹּט יְהוָה בֵּינִי וּבֵינֶיךָ׃
וַיֹּאמֶר אַבְרָם אֶל־שָׂרַי הִנֵּה שִׁפְחָתֵךְ בְּיָדֵךְ עֲשִׂי־לָהּ הַטּוֹב בְּעֵינָיִךְ וַתְּעַנֶּהָ שָׂרַי וַתִּבְרַח מִפָּנֶיהָ׃
וַיִּמְצָאָהּ מַלְאַךְ יְהוָה עַל־עֵין הַמַּיִם בַּמִּדְבָּר עַל־הָעַיִן בְּדֶרֶךְ שׁוּר׃
וַיֹּאמַר הָגָר שִׁפְחַת שָׂרַי אֵי־מִזֶּה בָאת וְאָנָה תֵלֵכִי וַתֹּאמֶר מִפְּנֵי שָׂרַי גְּבִרְתִּי אָנֹכִי בֹּרַחַת׃
וַיֹּאמֶר לָהּ מַלְאַךְ יְהוָה שׁוּבִי אֶל־גְּבִרְתֵּךְ וְהִתְעַנִּי תַּחַת יָדֶיהָ׃
וַיֹּאמֶר לָהּ מַלְאַךְ יְהוָה הַרְבָּה אַרְבֶּה אֶת־זַרְעֵךְ וְלֹא יִסָּפֵר מֵרֹב׃
וַיֹּאמֶר לָהּ מַלְאַךְ יְהוָה הִנָּךְ הָרָה וְיֹלַדְתְּ בֵּן וְקָרָאת שְׁמוֹ יִשְׁמָעֵאל כִּי־שָׁמַע יְהוָה אֶל־עָנְיֵךְ׃
וְהוּא יִהְיֶה פֶּרֶא אָדָם יָדוֹ בַכֹּל וְיַד כֹּל בּוֹ וְעַל־פְּנֵי כָל־אֶחָיו יִשְׁכֹּן׃
וַתִּקְרָא שֵׁם־יְהוָה הַדֹּבֵר אֵלֶיהָ אַתָּה אֵל רֳאִי כִּי אָמְרָה הֲגַם הֲלֹם רָאִיתִי אַחֲרֵי רֹאִי׃
עַל־כֵּן קָרָא לַבְּאֵר בְּאֵר לַחַי רֹאִי הִנֵּה בֵין־קָדֵשׁ וּבֵין בָּרֶד׃
וַתֵּלֶד הָגָר לְאַבְרָם בֵּן וַיִּקְרָא אַבְרָם שֶׁם־בְּנוֹ אֲשֶׁר־יָלְדָה הָגָר יִשְׁמָעֵאל׃
וְאַבְרָם בֶּן־שְׁמֹנִים שָׁנָה וְשֵׁשׁ שָׁנִים בְּלֶדֶת־הָגָר אֶת־יִשְׁמָעֵאל לְאַבְרָם׃

Chapter 17

וַיְהִי אַבְרָם בֶּן־תִּשְׁעִים שָׁנָה וְתֵשַׁע שָׁנִים וַיֵּרָא יְהוָה אֶל־אַבְרָם וַיֹּאמֶר אֵלָיו אֲנִי־אֵל שַׁדַּי הִתְהַלֵּךְ לְפָנַי וֶהְיֵה תָמִים׃
וְאֶתְּנָה בְרִיתִי בֵּינִי וּבֵינֶךָ וְאַרְבֶּה אוֹתְךָ בִּמְאֹד מְאֹד׃
וַיִּפֹּל אַבְרָם עַל־פָּנָיו וַיְדַבֵּר אִתּוֹ אֱלֹהִים לֵאמֹר׃
אֲנִי הִנֵּה בְרִיתִי אִתָּךְ וְהָיִיתָ לְאַב הֲמוֹן גּוֹיִם׃
וְלֹא־יִקָּרֵא עוֹד אֶת־שִׁמְךָ אַבְרָם וְהָיָה שִׁמְךָ אַבְרָהָם כִּי אַב־הֲמוֹן גּוֹיִם נְתַתִּיךָ׃
וְהִפְרֵתִי אֹתְךָ בִּמְאֹד מְאֹד וּנְתַתִּיךָ לְגוֹיִם וּמְלָכִים מִמְּךָ יֵצֵאוּ׃
וַהֲקִמֹתִי אֶת־בְּרִיתִי בֵּינִי וּבֵינֶךָ וּבֵין זַרְעֲךָ אַחֲרֶיךָ לְדֹרֹתָם לִבְרִית עוֹלָם לִהְיוֹת לְךָ לֵאלֹהִים וּלְזַרְעֲךָ אַחֲרֶיךָ׃
וְנָתַתִּי לְךָ וּלְזַרְעֲךָ אַחֲרֶיךָ אֵת אֶרֶץ מְגֻרֶיךָ אֵת כָּל־אֶרֶץ כְּנַעַן לַאֲחֻזַּת עוֹלָם וְהָיִיתִי לָהֶם לֵאלֹהִים׃
וַיֹּאמֶר אֱלֹהִים אֶל־אַבְרָהָם וְאַתָּה אֶת־בְּרִיתִי תִשְׁמֹר אַתָּה וְזַרְעֲךָ אַחֲרֶיךָ לְדֹרֹתָם׃
זֹאת בְּרִיתִי אֲשֶׁר תִּשְׁמְרוּ בֵּינִי וּבֵינֵיכֶם וּבֵין זַרְעֲךָ אַחֲרֶיךָ הִמּוֹל לָכֶם כָּל־זָכָר׃
וּנְמַלְתֶּם אֵת בְּשַׂר עָרְלַתְכֶם וְהָיָה לְאוֹת בְּרִית בֵּינִי וּבֵינֵיכֶם׃
וּבֶן־שְׁמֹנַת יָמִים יִמּוֹל לָכֶם כָּל־זָכָר לְדֹרֹתֵיכֶם יְלִיד בָּיִת וּמִקְנַת־כֶּסֶף מִכֹּל בֶּן־נֵכָר אֲשֶׁר לֹא מִזַּרְעֲךָ הוּא׃
הִמּוֹל יִמּוֹל יְלִיד בֵּיתְךָ וּמִקְנַת כַּסְפֶּךָ וְהָיְתָה בְרִיתִי בִּבְשַׂרְכֶם לִבְרִית עוֹלָם׃
וְעָרֵל זָכָר אֲשֶׁר לֹא־יִמּוֹל אֶת־בְּשַׂר עָרְלָתוֹ וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מֵעַמֶּיהָ אֶת־בְּרִיתִי הֵפַר׃
וַיֹּאמֶר אֱלֹהִים אֶל־אַבְרָהָם שָׂרַי אִשְׁתְּךָ לֹא־תִקְרָא אֶת־שְׁמָהּ שָׂרָי כִּי שָׂרָה שְׁמָהּ׃
וּבֵרַכְתִּי אֹתָהּ וְגַם נָתַתִּי מִמֶּנָּה לְךָ בֵּן וּבֵרַכְתִּיהָ וְהָיְתָה לְגוֹיִם מַלְכֵי עַמִּים מִמֶּנָּה יִהְיוּ׃
וַיִּפֹּל אַבְרָהָם עַל־פָּנָיו וַיִּצְחָק וַיֹּאמֶר בְּלִבּוֹ הַלְּבֶן מֵאָה־שָׁנָה יִוָּלֵד וְאִם־שָׂרָה הֲבַת־תִּשְׁעִים שָׁנָה תֵּלֵד׃
וַיֹּאמֶר אַבְרָהָם אֶל־הָאֱלֹהִים לוּ יִשְׁמָעֵאל יִחְיֶה לְפָנֶיךָ׃
וַיֹּאמֶר אֱלֹהִים אֲבָל שָׂרָה אִשְׁתְּךָ יֹלֶדֶת לְךָ בֵּן וְקָרָאתָ אֶת־שְׁמוֹ יִצְחָק וַהֲקִמֹתִי אֶת־בְּרִיתִי אִתּוֹ לִבְרִית עוֹלָם לְזַרְעוֹ אַחֲרָיו׃
וּלְיִשְׁמָעֵאל שְׁמַעְתִּיךָ הִנֵּה בֵּרַכְתִּי אֹתוֹ וְהִפְרֵיתִי אֹתוֹ וְהִרְבֵּיתִי אֹתוֹ בִּמְאֹד מְאֹד שְׁנֵים־עָשָׂר נְשִׂיאִם יוֹלִיד וּנְתַתִּיו לְגוֹי גָּדוֹל׃
וְאֶת־בְּרִיתִי אָקִים אֶת־יִצְחָק אֲשֶׁר תֵּלֵד לְךָ שָׂרָה לַמּוֹעֵד הַזֶּה בַּשָּׁנָה הָאַחֶרֶת׃
וַיְכַל לְדַבֵּר אִתּוֹ וַיַּעַל אֱלֹהִים מֵעַל אַבְרָהָם׃
וַיִּקַּח אַבְרָהָם אֶת־יִשְׁמָעֵאל בְּנוֹ וְאֵת כָּל־יְלִידֵי בֵיתוֹ וְאֵת כָּל־מִקְנַת כַּסְפּוֹ כָּל־זָכָר בְּאַנְשֵׁי בֵּית אַבְרָהָם וַיָּמָל אֶת־בְּשַׂר עָרְלָתָם בְּעֶצֶם הַיּוֹם הַזֶּה כַּאֲשֶׁר דִּבֶּר אִתּוֹ אֱלֹהִים׃
וְאַבְרָהָם בֶּן־תִּשְׁעִים וָתֵשַׁע שָׁנָה בְּהִמֹּלוֹ בְּשַׂר עָרְלָתוֹ׃
וְיִשְׁמָעֵאל בְּנוֹ בֶּן־שְׁלֹשׁ עֶשְׂרֵה שָׁנָה בְּהִמֹּלוֹ אֵת בְּשַׂר עָרְלָתוֹ׃
בְּעֶצֶם הַיּוֹם הַזֶּה נִמּוֹל אַבְרָהָם וְיִשְׁמָעֵאל בְּנוֹ׃
וְכָל־אַנְשֵׁי בֵיתוֹ יְלִיד בָּיִת וּמִקְנַת־כֶּסֶף מֵאֵת בֶּן־נֵכָר נִמֹּלוּ אִתּוֹ׃

Chapter 18

וַיֵּרָא אֵלָיו יְהוָה בְּאֵלֹנֵי מַמְרֵא וְהוּא יֹשֵׁב פֶּתַח־הָאֹהֶל כְּחֹם הַיּוֹם׃
וַיִּשָּׂא עֵינָיו וַיַּרְא וְהִנֵּה שְׁלֹשָׁה אֲנָשִׁים נִצָּבִים עָלָיו וַיַּרְא וַיָּרָץ לִקְרָאתָם מִפֶּתַח הָאֹהֶל וַיִּשְׁתַּחוּ אָרְצָה׃
וַיֹּאמַר אֲדֹנָי אִם־נָא מָצָאתִי חֵן בְּעֵינֶיךָ אַל־נָא תַעֲבֹר מֵעַל עַבְדֶּךָ׃
יֻקַּח־נָא מְעַט־מַיִם וְרַחֲצוּ רַגְלֵיכֶם וְהִשָּׁעֲנוּ תַּחַת הָעֵץ׃
וְאֶקְחָה פַת־לֶחֶם וְסַעֲדוּ לִבְּכֶם אַחַר תַּעֲבֹרוּ כִּי־עַל־כֵּן עֲבַרְתֶּם עַל־עַבְדְּכֶם וַיֹּאמְרוּ כֵּן תַּעֲשֶׂה כַּאֲשֶׁר דִּבַּרְתָּ׃
וַיְמַהֵר אַבְרָהָם הָאֹהֱלָה אֶל־שָׂרָה וַיֹּאמֶר מַהֲרִי שְׁלֹשׁ סְאִים קֶמַח סֹלֶת לוּשִׁי וַעֲשִׂי עֻגוֹת׃
וְאֶל־הַבָּקָר רָץ אַבְרָהָם וַיִּקַּח בֶּן־בָּקָר רַךְ וָטוֹב וַיִּתֵּן אֶל־הַנַּעַר וַיְמַהֵר לַעֲשׂוֹת אֹתוֹ׃
וַיִּקַּח חֶמְאָה וְחָלָב וּבֶן־הַבָּקָר אֲשֶׁר עָשָׂה וַיִּתֵּן לִפְנֵיהֶם וְהוּא־עֹמֵד עֲלֵיהֶם תַּחַת הָעֵץ וַיֹּאכֵלוּ׃
וַיֹּאמְרוּ אֵלָיו אַיֵּה שָׂרָה אִשְׁתֶּךָ וַיֹּאמֶר הִנֵּה בָאֹהֶל׃
וַיֹּאמֶר שׁוֹב אָשׁוּב אֵלֶיךָ כָּעֵת חַיָּה וְהִנֵּה־בֵן לְשָׂרָה אִשְׁתֶּךָ וְשָׂרָה שֹׁמַעַת פֶּתַח הָאֹהֶל וְהוּא אַחֲרָיו׃
וְאַבְרָהָם וְשָׂרָה זְקֵנִים בָּאִים בַּיָּמִים חָדַל לִהְיוֹת לְשָׂרָה אֹרַח כַּנָּשִׁים׃
וַתִּצְחַק שָׂרָה בְּקִרְבָּהּ לֵאמֹר אַחֲרֵי בְלֹתִי הָיְתָה־לִּי עֶדְנָה וַאדֹנִי זָקֵן׃
וַיֹּאמֶר יְהוָה אֶל־אַבְרָהָם לָמָּה זֶּה צָחֲקָה שָׂרָה לֵאמֹר הַאַף אֻמְנָם אֵלֵד וַאֲנִי זָקַנְתִּי׃
הֲיִפָּלֵא מֵיְהוָה דָּבָר לַמּוֹעֵד אָשׁוּב אֵלֶיךָ כָּעֵת חַיָּה וּלְשָׂרָה בֵן׃
וַתְּכַחֵשׁ שָׂרָה לֵאמֹר לֹא צָחַקְתִּי כִּי יָרֵאָה וַיֹּאמֶר לֹא כִּי צָחָקְתְּ׃
וַיָּקֻמוּ מִשָּׁם הָאֲנָשִׁים וַיַּשְׁקִפוּ עַל־פְּנֵי סְדֹם וְאַבְרָהָם הֹלֵךְ עִמָּם לְשַׁלְּחָם׃
וַיהֹוָה אָמָר הַמְכַסֶּה אֲנִי מֵאַבְרָהָם אֲשֶׁר אֲנִי עֹשֶׂה׃
וְאַבְרָהָם הָיוֹ יִהְיֶה לְגוֹי גָּדוֹל וְעָצוּם וְנִבְרְכוּ בוֹ כֹּל גּוֹיֵי הָאָרֶץ׃
כִּי יְדַעְתִּיו לְמַעַן אֲשֶׁר יְצַוֶּה אֶת־בָּנָיו וְאֶת־בֵּיתוֹ אַחֲרָיו וְשָׁמְרוּ דֶּרֶךְ יְהוָה לַעֲשׂוֹת צְדָקָה וּמִשְׁפָּט לְמַעַן הָבִיא יְהוָה עַל־אַבְרָהָם אֵת אֲשֶׁר־דִּבֶּר עָלָיו׃
וַיֹּאמֶר יְהוָה זַעֲקַת סְדֹם וַעֲמֹרָה כִּי־רָבָּה וְחַטָּאתָם כִּי כָבְדָה מְאֹד׃
אֵרֲדָה־נָּא וְאֶרְאֶה הַכְּצַעֲקָתָהּ הַבָּאָה אֵלַי עָשׂוּ כָּלָה וְאִם־לֹא אֵדָעָה׃
וַיִּפְנוּ מִשָּׁם הָאֲנָשִׁים וַיֵּלְכוּ סְדֹמָה וְאַבְרָהָם עוֹדֶנּוּ עֹמֵד לִפְנֵי יְהוָה׃
וַיִּגַּשׁ אַבְרָהָם וַיֹּאמַר הַאַף תִּסְפֶּה צַדִּיק עִם־רָשָׁע׃
אוּלַי יֵשׁ חֲמִשִּׁים צַדִּיקִם בְּתוֹךְ הָעִיר הַאַף תִּסְפֶּה וְלֹא־תִשָּׂא לַמָּקוֹם לְמַעַן חֲמִשִּׁים הַצַּדִּיקִם אֲשֶׁר בְּקִרְבָּהּ׃
חָלִלָה לְּךָ מֵעֲשֹׂת כַּדָּבָר הַזֶּה לְהָמִית צַדִּיק עִם־רָשָׁע וְהָיָה כַצַּדִּיק כָּרָשָׁע חָלִלָה לָּךְ הֲשֹׁפֵט כָּל־הָאָרֶץ לֹא יַעֲשֶׂה מִשְׁפָּט׃
וַיֹּאמֶר יְהוָה אִם־אֶמְצָא בִסְדֹם חֲמִשִּׁים צַדִּיקִם בְּתוֹךְ הָעִיר וְנָשָׂאתִי לְכָל־הַמָּקוֹם בַּעֲבוּרָם׃
וַיַּעַן אַבְרָהָם וַיֹּאמַר הִנֵּה־נָא הוֹאַלְתִּי לְדַבֵּר אֶל־אֲדֹנָי וְאָנֹכִי עָפָר וָאֵפֶר׃
אוּלַי יַחְסְרוּן חֲמִשִּׁים הַצַּדִּיקִם חֲמִשָּׁה הֲתַשְׁחִית בַּחֲמִשָּׁה אֶת־כָּל־הָעִיר וַיֹּאמֶר לֹא אַשְׁחִית אִם־אֶמְצָא שָׁם אַרְבָּעִים וַחֲמִשָּׁה׃
וַיֹּסֶף עוֹד לְדַבֵּר אֵלָיו וַיֹּאמַר אוּלַי יִמָּצְאוּן שָׁם אַרְבָּעִים וַיֹּאמֶר לֹא אֶעֱשֶׂה בַּעֲבוּר הָאַרְבָּעִים׃
וַיֹּאמֶר אַל־נָא יִחַר לַאדֹנָי וַאֲדַבֵּרָה אוּלַי יִמָּצְאוּן שָׁם שְׁלֹשִׁים וַיֹּאמֶר לֹא אֶעֱשֶׂה אִם־אֶמְצָא שָׁם שְׁלֹשִׁים׃
וַיֹּאמֶר הִנֵּה־נָא הוֹאַלְתִּי לְדַבֵּר אֶל־אֲדֹנָי אוּלַי יִמָּצְאוּן שָׁם עֶשְׂרִים וַיֹּאמֶר לֹא אַשְׁחִית בַּעֲבוּר הָעֶשְׂרִים׃
וַיֹּאמֶר אַל־נָא יִחַר לַאדֹנָי וַאֲדַבְּרָה אַךְ־הַפַּעַם אוּלַי יִמָּצְאוּן שָׁם עֲשָׂרָה וַיֹּאמֶר לֹא אַשְׁחִית בַּעֲבוּר הָעֲשָׂרָה׃
וַיֵּלֶךְ יְהוָה כַּאֲשֶׁר כִּלָּה לְדַבֵּר אֶל־אַבְרָהָם וְאַבְרָהָם שָׁב לִמְקֹמוֹ׃

Chapter 19

וַיָּבֹאוּ שְׁנֵי הַמַּלְאָכִים סְדֹמָה בָּעֶרֶב וְלוֹט יֹשֵׁב בְּשַׁעַר־סְדֹם וַיַּרְא־לוֹט וַיָּקָם לִקְרָאתָם וַיִּשְׁתַּחוּ אַפַּיִם אָרְצָה׃
וַיֹּאמֶר הִנֶּה נָּא־אֲדֹנַי סוּרוּ נָא אֶל־בֵּית עַבְדְּכֶם וְלִינוּ וְרַחֲצוּ רַגְלֵיכֶם וְהִשְׁכַּמְתֶּם וַהֲלַכְתֶּם לְדַרְכְּכֶם וַיֹּאמְרוּ לֹּא כִּי בָרְחוֹב נָלִין׃
וַיִּפְצַר־בָּם מְאֹד וַיָּסֻרוּ אֵלָיו וַיָּבֹאוּ אֶל־בֵּיתוֹ וַיַּעַשׂ לָהֶם מִשְׁתֶּה וּמַצּוֹת אָפָה וַיֹּאכֵלוּ׃
טֶרֶם יִשְׁכָּבוּ וְאַנְשֵׁי הָעִיר אַנְשֵׁי סְדֹם נָסַבּוּ עַל־הַבַּיִת מִנַּעַר וְעַד־זָקֵן כָּל־הָעָם מִקָּצֶה׃
וַיִּקְרְאוּ אֶל־לוֹט וַיֹּאמְרוּ לוֹ אַיֵּה הָאֲנָשִׁים אֲשֶׁר־בָּאוּ אֵלֶיךָ הַלָּיְלָה הוֹצִיאֵם אֵלֵינוּ וְנֵדְעָה אֹתָם׃
וַיֵּצֵא אֲלֵהֶם לוֹט הַפֶּתְחָה וְהַדֶּלֶת סָגַר אַחֲרָיו׃
וַיֹּאמַר אַל־נָא אַחַי תָּרֵעוּ׃
הִנֵּה־נָא לִי שְׁתֵּי בָנוֹת אֲשֶׁר לֹא־יָדְעוּ אִישׁ אוֹצִיאָה־נָּא אֶתְהֶן אֲלֵיכֶם וַעֲשׂוּ לָהֶן כַּטּוֹב בְּעֵינֵיכֶם רַק לָאֲנָשִׁים הָאֵל אַל־תַּעֲשׂוּ דָבָר כִּי־עַל־כֵּן בָּאוּ בְּצֵל קֹרָתִי׃
וַיֹּאמְרוּ גֶּשׁ־הָלְאָה וַיֹּאמְרוּ הָאֶחָד בָּא־לָגוּר וַיִּשְׁפֹּט שָׁפוֹט עַתָּה נָרַע לְךָ מֵהֶם וַיִּפְצְרוּ בָאִישׁ בְּלוֹט מְאֹד וַיִּגְּשׁוּ לִשְׁבֹּר הַדָּלֶת׃
וַיִּשְׁלְחוּ הָאֲנָשִׁים אֶת־יָדָם וַיָּבִיאוּ אֶת־לוֹט אֲלֵיהֶם הַבָּיְתָה וְאֶת־הַדֶּלֶת סָגָרוּ׃
וְאֶת־הָאֲנָשִׁים אֲשֶׁר־פֶּתַח הַבַּיִת הִכּוּ בַּסַּנְוֵרִים מִקָּטֹן וְעַד־גָּדוֹל וַיִּלְאוּ לִמְצֹא הַפָּתַח׃
וַיֹּאמְרוּ הָאֲנָשִׁים אֶל־לוֹט עֹד מִי־לְךָ פֹה חָתָן וּבָנֶיךָ וּבְנֹתֶיךָ וְכֹל אֲשֶׁר־לְךָ בָּעִיר הוֹצֵא מִן־הַמָּקוֹם׃
כִּי־מַשְׁחִתִים אֲנַחְנוּ אֶת־הַמָּקוֹם הַזֶּה כִּי־גָדְלָה צַעֲקָתָם אֶת־פְּנֵי יְהוָה וַיְשַׁלְּחֵנוּ יְהוָה לְשַׁחֲתָהּ׃
וַיֵּצֵא לוֹט וַיְדַבֵּר אֶל־חֲתָנָיו לֹקְחֵי בְנֹתָיו וַיֹּאמֶר קוּמוּ צְּאוּ מִן־הַמָּקוֹם הַזֶּה כִּי־מַשְׁחִית יְהוָה אֶת־הָעִיר וַיְהִי כִמְצַחֵק בְּעֵינֵי חֲתָנָיו׃
וּכְמוֹ הַשַּׁחַר עָלָה וַיָּאִיצוּ הַמַּלְאָכִים בְּלוֹט לֵאמֹר קוּם קַח אֶת־אִשְׁתְּךָ וְאֶת־שְׁתֵּי בְנֹתֶיךָ הַנִּמְצָאֹת פֶּן־תִּסָּפֶה בַּעֲוֺן הָעִיר׃
וַיִּתְמַהְמָהּ וַיַּחֲזִקוּ הָאֲנָשִׁים בְּיָדוֹ וּבְיַד־אִשְׁתּוֹ וּבְיַד שְׁתֵּי בְנֹתָיו בְּחֶמְלַת יְהוָה עָלָיו וַיֹּצִאֻהוּ וַיַּנִּחֻהוּ מִחוּץ לָעִיר׃
וַיְהִי כְהוֹצִיאָם אֹתָם הַחוּצָה וַיֹּאמֶר הִמָּלֵט עַל־נַפְשֶׁךָ אַל־תַּבִּיט אַחֲרֶיךָ וְאַל־תַּעֲמֹד בְּכָל־הַכִּכָּר הָהָרָה הִמָּלֵט פֶּן־תִּסָּפֶה׃
וַיֹּאמֶר לוֹט אֲלֵהֶם אַל־נָא אֲדֹנָי׃
הִנֵּה־נָא מָצָא עַבְדְּךָ חֵן בְּעֵינֶיךָ וַתַּגְדֵּל חַסְדְּךָ אֲשֶׁר עָשִׂיתָ עִמָּדִי לְהַחֲיוֹת אֶת־נַפְשִׁי וְאָנֹכִי לֹא אוּכַל לְהִמָּלֵט הָהָרָה פֶּן־תִּדְבָּקַנִי הָרָעָה וָמַתִּי׃
הִנֵּה־נָא הָעִיר הַזֹּאת קְרֹבָה לָנוּס שָׁמָּה וְהִיא מִצְעָר אִמָּלְטָה נָּא שָׁמָּה הֲלֹא מִצְעָר הִוא וּתְחִי נַפְשִׁי׃
וַיֹּאמֶר אֵלָיו הִנֵּה נָשָׂאתִי פָנֶיךָ גַּם לַדָּבָר הַזֶּה לְבִלְתִּי הָפְכִּי אֶת־הָעִיר אֲשֶׁר דִּבַּרְתָּ׃
מַהֵר הִמָּלֵט שָׁמָּה כִּי לֹא אוּכַל לַעֲשׂוֹת דָּבָר עַד־בֹּאֲךָ שָׁמָּה עַל־כֵּן קָרָא שֵׁם־הָעִיר צוֹעַר׃
הַשֶּׁמֶשׁ יָצָא עַל־הָאָרֶץ וְלוֹט בָּא צֹעֲרָה׃
וַיהוָה הִמְטִיר עַל־סְדֹם וְעַל־עֲמֹרָה גָּפְרִית וָאֵשׁ מֵאֵת יְהוָה מִן־הַשָּׁמָיִם׃
וַיַּהֲפֹךְ אֶת־הֶעָרִים הָאֵל וְאֵת כָּל־הַכִּכָּר וְאֵת כָּל־יֹשְׁבֵי הֶעָרִים וְצֶמַח הָאֲדָמָה׃
וַתַּבֵּט אִשְׁתּוֹ מֵאַחֲרָיו וַתְּהִי נְצִיב מֶלַח׃
וַיַּשְׁכֵּם אַבְרָהָם בַּבֹּקֶר אֶל־הַמָּקוֹם אֲשֶׁר־עָמַד שָׁם אֶת־פְּנֵי יְהוָה׃
וַיַּשְׁקֵף עַל־פְּנֵי סְדֹם וַעֲמֹרָה וְעַל־כָּל־פְּנֵי אֶרֶץ הַכִּכָּר וַיַּרְא וְהִנֵּה עָלָה קִיטֹר הָאָרֶץ כְּקִיטֹר הַכִּבְשָׁן׃
וַיְהִי בְּשַׁחֵת אֱלֹהִים אֶת־עָרֵי הַכִּכָּר וַיִּזְכֹּר אֱלֹהִים אֶת־אַבְרָהָם וַיְשַׁלַּח אֶת־לוֹט מִתּוֹךְ הַהֲפֵכָה בַּהֲפֹךְ אֶת־הֶעָרִים אֲשֶׁר־יָשַׁב בָּהֵן לוֹט׃
וַיַּעַל לוֹט מִצּוֹעַר וַיֵּשֶׁב בָּהָר וּשְׁתֵּי בְנֹתָיו עִמּוֹ כִּי יָרֵא לָשֶׁבֶת בְּצוֹעַר וַיֵּשֶׁב בַּמְּעָרָה הוּא וּשְׁתֵּי בְנֹתָיו׃
וַתֹּאמֶר הַבְּכִירָה אֶל־הַצְּעִירָה אָבִינוּ זָקֵן וְאִישׁ אֵין בָּאָרֶץ לָבוֹא עָלֵינוּ כְּדֶרֶךְ כָּל־הָאָרֶץ׃
לְכָה נַשְׁקֶה אֶת־אָבִינוּ יַיִן וְנִשְׁכְּבָה עִמּוֹ וּנְחַיֶּה מֵאָבִינוּ זָרַע׃
וַתַּשְׁקֶיןָ אֶת־אֲבִיהֶן יַיִן בַּלַּיְלָה הוּא וַתָּבֹא הַבְּכִירָה וַתִּשְׁכַּב אֶת־אָבִיהָ וְלֹא־יָדַע בְּשִׁכְבָהּ וּבְקוּמָהּ׃
וַיְהִי מִמָּחֳרָת וַתֹּאמֶר הַבְּכִירָה אֶל־הַצְּעִירָה הֵן־שָׁכַבְתִּי אֶמֶשׁ אֶת־אָבִי נַשְׁקֶנּוּ יַיִן גַּם־הַלַּיְלָה וּבֹאִי שִׁכְבִי עִמּוֹ וּנְחַיֶּה מֵאָבִינוּ זָרַע׃
וַתַּשְׁקֶיןָ גַּם בַּלַּיְלָה הַהוּא אֶת־אֲבִיהֶן יָיִן וַתָּקָם הַצְּעִירָה וַתִּשְׁכַּב עִמּוֹ וְלֹא־יָדַע בְּשִׁכְבָהּ וּבְקֻמָהּ׃
וַתַּהֲרֶיןָ שְׁתֵּי בְנוֹת־לוֹט מֵאֲבִיהֶן׃
וַתֵּלֶד הַבְּכִירָה בֵּן וַתִּקְרָא שְׁמוֹ מוֹאָב הוּא אֲבִי־מוֹאָב עַד־הַיּוֹם׃
וְהַצְּעִירָה גַם־הִוא יָלְדָה בֵּן וַתִּקְרָא שְׁמוֹ בֶּן־עַמִּי הוּא אֲבִי בְנֵי־עַמּוֹן עַד־הַיּוֹם׃

Chapter 20

וַיִּסַּע מִשָּׁם אַבְרָהָם אַרְצָה הַנֶּגֶב וַיֵּשֶׁב בֵּין־קָדֵשׁ וּבֵין שׁוּר וַיָּגָר בִּגְרָר׃
וַיֹּאמֶר אַבְרָהָם אֶל־שָׂרָה אִשְׁתּוֹ אֲחֹתִי הִוא וַיִּשְׁלַח אֲבִימֶלֶךְ מֶלֶךְ גְּרָר וַיִּקַּח אֶת־שָׂרָה׃
וַיָּבֹא אֱלֹהִים אֶל־אֲבִימֶלֶךְ בַּחֲלוֹם הַלָּיְלָה וַיֹּאמֶר לוֹ הִנְּךָ מֵת עַל־הָאִשָּׁה אֲשֶׁר־לָקַחְתָּ וְהִוא בְּעֻלַת בָּעַל׃
וַאֲבִימֶלֶךְ לֹא קָרַב אֵלֶיהָ וַיֹּאמַר אֲדֹנָי הֲגוֹי גַּם־צַדִּיק תַּהֲרֹג׃
הֲלֹא הוּא אָמַר־לִי אֲחֹתִי הִוא וְהִיא־גַם־הִוא אָמְרָה אָחִי הוּא בְּתָם־לְבָבִי וּבְנִקְיֹן כַּפַּי עָשִׂיתִי זֹאת׃
וַיֹּאמֶר אֵלָיו הָאֱלֹהִים בַּחֲלֹם גַּם אָנֹכִי יָדַעְתִּי כִּי בְתָם־לְבָבְךָ עָשִׂיתָ זֹּאת וָאֶחְשֹׂךְ גַּם־אָנֹכִי אוֹתְךָ מֵחֲטוֹ־לִי עַל־כֵּן לֹא־נְתַתִּיךָ לִנְגֹּעַ אֵלֶיהָ׃
וְעַתָּה הָשֵׁב אֵשֶׁת־הָאִישׁ כִּי־נָבִיא הוּא וְיִתְפַּלֵּל בַּעַדְךָ וֶחְיֵה וְאִם־אֵינְךָ מֵשִׁיב דַּע כִּי־מוֹת תָּמוּת אַתָּה וְכָל־אֲשֶׁר־לָךְ׃
וַיַּשְׁכֵּם אֲבִימֶלֶךְ בַּבֹּקֶר וַיִּקְרָא לְכָל־עֲבָדָיו וַיְדַבֵּר אֶת־כָּל־הַדְּבָרִים הָאֵלֶּה בְּאָזְנֵיהֶם וַיִּירְאוּ הָאֲנָשִׁים מְאֹד׃
וַיִּקְרָא אֲבִימֶלֶךְ לְאַבְרָהָם וַיֹּאמֶר לוֹ מֶה־עָשִׂיתָ לָּנוּ וּמֶה־חָטָאתִי לָךְ כִּי־הֵבֵאתָ עָלַי וְעַל־מַמְלַכְתִּי חֲטָאָה גְדֹלָה מַעֲשִׂים אֲשֶׁר לֹא־יֵעָשׂוּ עָשִׂיתָ עִמָּדִי׃
וַיֹּאמֶר אֲבִימֶלֶךְ אֶל־אַבְרָהָם מָה רָאִיתָ כִּי עָשִׂיתָ אֶת־הַדָּבָר הַזֶּה׃
וַיֹּאמֶר אַבְרָהָם כִּי אָמַרְתִּי רַק אֵין־יִרְאַת אֱלֹהִים בַּמָּקוֹם הַזֶּה וַהֲרָגוּנִי עַל־דְּבַר אִשְׁתִּי׃
וְגַם־אָמְנָה אֲחֹתִי בַת־אָבִי הִוא אַךְ לֹא בַת־אִמִּי וַתְּהִי־לִי לְאִשָּׁה׃
וַיְהִי כַּאֲשֶׁר הִתְעוּ אֹתִי אֱלֹהִים מִבֵּית אָבִי וָאֹמַר לָהּ זֶה חַסְדֵּךְ אֲשֶׁר תַּעֲשִׂי עִמָּדִי אֶל כָּל־הַמָּקוֹם אֲשֶׁר נָבוֹא שָׁמָּה אִמְרִי־לִי אָחִי הוּא׃
וַיִּקַּח אֲבִימֶלֶךְ צֹאן וּבָקָר וַעֲבָדִים וּשְׁפָחֹת וַיִּתֵּן לְאַבְרָהָם וַיָּשֶׁב לוֹ אֵת שָׂרָה אִשְׁתּוֹ׃
וַיֹּאמֶר אֲבִימֶלֶךְ הִנֵּה אַרְצִי לְפָנֶיךָ בַּטּוֹב בְּעֵינֶיךָ שֵׁב׃
וּלְשָׂרָה אָמַר הִנֵּה נָתַתִּי אֶלֶף כֶּסֶף לְאָחִיךְ הִנֵּה הוּא־לָךְ כְּסוּת עֵינַיִם לְכֹל אֲשֶׁר אִתָּךְ וְאֵת כֹּל וְנֹכָחַת׃
וַיִּתְפַּלֵּל אַבְרָהָם אֶל־הָאֱלֹהִים וַיִּרְפָּא אֱלֹהִים אֶת־אֲבִימֶלֶךְ וְאֶת־אִשְׁתּוֹ וְאַמְהֹתָיו וַיֵּלֵדוּ׃
כִּי־עָצֹר עָצַר יְהוָה בְּעַד כָּל־רֶחֶם לְבֵית אֲבִימֶלֶךְ עַל־דְּבַר שָׂרָה אֵשֶׁת אַבְרָהָם׃

Chapter 21

וַיהוָה פָּקַד אֶת־שָׂרָה כַּאֲשֶׁר אָמָר וַיַּעַשׂ יְהוָה לְשָׂרָה כַּאֲשֶׁר דִּבֵּר׃
וַתַּהַר וַתֵּלֶד שָׂרָה לְאַבְרָהָם בֵּן לִזְקֻנָיו לַמּוֹעֵד אֲשֶׁר־דִּבֶּר אֹתוֹ אֱלֹהִים׃
וַיִּקְרָא אַבְרָהָם אֶת־שֶׁם־בְּנוֹ הַנּוֹלַד־לוֹ אֲשֶׁר־יָלְדָה־לּוֹ שָׂרָה יִצְחָק׃
וַיָּמָל אַבְרָהָם אֶת־יִצְחָק בְּנוֹ בֶּן־שְׁמֹנַת יָמִים כַּאֲשֶׁר צִוָּה אֹתוֹ אֱלֹהִים׃
וְאַבְרָהָם בֶּן־מְאַת שָׁנָה בְּהִוָּלֶד לוֹ אֵת יִצְחָק בְּנוֹ׃
וַתֹּאמֶר שָׂרָה צְחֹק עָשָׂה לִי אֱלֹהִים כָּל־הַשֹּׁמֵעַ יִצְחַק־לִי׃
וַתֹּאמֶר מִי מִלֵּל לְאַבְרָהָם הֵינִיקָה בָנִים שָׂרָה כִּי־יָלַדְתִּי בֵן לִזְקֻנָיו׃
וַיִּגְדַּל הַיֶּלֶד וַיִּגָּמַל וַיַּעַשׂ אַבְרָהָם מִשְׁתֶּה גָדוֹל בְּיוֹם הִגָּמֵל אֶת־יִצְחָק׃
וַתֵּרֶא שָׂרָה אֶת־בֶּן־הָגָר הַמִּצְרִית אֲשֶׁר־יָלְדָה לְאַבְרָהָם מְצַחֵק׃
וַתֹּאמֶר לְאַבְרָהָם גָּרֵשׁ הָאָמָה הַזֹּאת וְאֶת־בְּנָהּ כִּי לֹא יִירַשׁ בֶּן־הָאָמָה הַזֹּאת עִם־בְּנִי עִם־יִצְחָק׃
וַיֵּרַע הַדָּבָר מְאֹד בְּעֵינֵי אַבְרָהָם עַל אוֹדֹת בְּנוֹ׃
וַיֹּאמֶר אֱלֹהִים אֶל־אַבְרָהָם אַל־יֵרַע בְּעֵינֶיךָ עַל־הַנַּעַר וְעַל־אֲמָתֶךָ כֹּל אֲשֶׁר תֹּאמַר אֵלֶיךָ שָׂרָה שְׁמַע בְּקֹלָהּ כִּי בְיִצְחָק יִקָּרֵא לְךָ זָרַע׃
וְגַם אֶת־בֶּן־הָאָמָה לְגוֹי אֲשִׂימֶנּוּ כִּי זַרְעֲךָ הוּא׃
וַיַּשְׁכֵּם אַבְרָהָם בַּבֹּקֶר וַיִּקַּח־לֶחֶם וְחֵמַת מַיִם וַיִּתֵּן אֶל־הָגָר שָׂם עַל־שִׁכְמָהּ וְאֶת־הַיֶּלֶד וַיְשַׁלְּחֶהָ וַתֵּלֶךְ וַתֵּתַע בְּמִדְבַּר בְּאֵר שָׁבַע׃
וַיִּכְלוּ הַמַּיִם מִן־הַחֵמֶת וַתַּשְׁלֵךְ אֶת־הַיֶּלֶד תַּחַת אַחַד הַשִּׂיחִם׃
וַתֵּלֶךְ וַתֵּשֶׁב לָהּ מִנֶּגֶד הַרְחֵק כִּמְטַחֲוֵי קֶשֶׁת כִּי אָמְרָה אַל־אֶרְאֶה בְּמוֹת הַיָּלֶד וַתֵּשֶׁב מִנֶּגֶד וַתִּשָּׂא אֶת־קֹלָהּ וַתֵּבְךְּ׃
וַיִּשְׁמַע אֱלֹהִים אֶת־קוֹל הַנַּעַר וַיִּקְרָא מַלְאַךְ אֱלֹהִים אֶל־הָגָר מִן־הַשָּׁמַיִם וַיֹּאמֶר לָהּ מַה־לָּךְ הָגָר אַל־תִּירְאִי כִּי־שָׁמַע אֱלֹהִים אֶל־קוֹל הַנַּעַר בַּאֲשֶׁר הוּא־שָׁם׃
קוּמִי שְׂאִי אֶת־הַנַּעַר וְהַחֲזִיקִי אֶת־יָדֵךְ בּוֹ כִּי־לְגוֹי גָּדוֹל אֲשִׂימֶנּוּ׃
וַיִּפְקַח אֱלֹהִים אֶת־עֵינֶיהָ וַתֵּרֶא בְּאֵר מָיִם וַתֵּלֶךְ וַתְּמַלֵּא אֶת־הַחֵמֶת מַיִם וַתַּשְׁקְ אֶת־הַנָּעַר׃
וַיְהִי אֱלֹהִים אֶת־הַנַּעַר וַיִּגְדָּל וַיֵּשֶׁב בַּמִּדְבָּר וַיְהִי רֹבֶה קַשָּׁת׃
וַיֵּשֶׁב בְּמִדְבַּר פָּארָן וַתִּקַּח־לוֹ אִמּוֹ אִשָּׁה מֵאֶרֶץ מִצְרָיִם׃
וַיְהִי בָּעֵת הַהִוא וַיֹּאמֶר אֲבִימֶלֶךְ וּפִיכֹל שַׂר־צְבָאוֹ אֶל־אַבְרָהָם לֵאמֹר אֱלֹהִים עִמְּךָ בְּכֹל אֲשֶׁר־אַתָּה עֹשֶׂה׃
וְעַתָּה הִשָּׁבְעָה לִּי בֵאלֹהִים הֵנָּה אִם־תִּשְׁקֹר לִי וּלְנִינִי וּלְנֶכְדִּי כַּחֶסֶד אֲשֶׁר־עָשִׂיתִי עִמְּךָ תַּעֲשֶׂה עִמָּדִי וְעִם־הָאָרֶץ אֲשֶׁר־גַּרְתָּה בָּהּ׃
וַיֹּאמֶר אַבְרָהָם אָנֹכִי אִשָּׁבֵעַ׃
וְהוֹכִחַ אַבְרָהָם אֶת־אֲבִימֶלֶךְ עַל־אֹדוֹת בְּאֵר הַמַּיִם אֲשֶׁר גָּזְלוּ עַבְדֵי אֲבִימֶלֶךְ׃
וַיֹּאמֶר אֲבִימֶלֶךְ לֹא יָדַעְתִּי מִי עָשָׂה אֶת־הַדָּבָר הַזֶּה וְגַם־אַתָּה לֹא־הִגַּדְתָּ לִּי וְגַם אָנֹכִי לֹא שָׁמַעְתִּי בִּלְתִּי הַיּוֹם׃
וַיִּקַּח אַבְרָהָם צֹאן וּבָקָר וַיִּתֵּן לַאֲבִימֶלֶךְ וַיִּכְרְתוּ שְׁנֵיהֶם בְּרִית׃
וַיַּצֵּב אַבְרָהָם אֶת־שֶׁבַע כִּבְשֹׂת הַצֹּאן לְבַדְּהֶן׃
וַיֹּאמֶר אֲבִימֶלֶךְ אֶל־אַבְרָהָם מָה הֵנָּה שֶׁבַע כְּבָשֹׂת הָאֵלֶּה אֲשֶׁר הִצַּבְתָּ לְבַדָּנָה׃
וַיֹּאמֶר כִּי אֶת־שֶׁבַע כְּבָשֹׂת תִּקַּח מִיָּדִי בַּעֲבוּר תִּהְיֶה־לִּי לְעֵדָה כִּי חָפַרְתִּי אֶת־הַבְּאֵר הַזֹּאת׃
עַל־כֵּן קָרָא לַמָּקוֹם הַהוּא בְּאֵר שָׁבַע כִּי שָׁם נִשְׁבְּעוּ שְׁנֵיהֶם׃
וַיִּכְרְתוּ בְרִית בִּבְאֵר שָׁבַע וַיָּקָם אֲבִימֶלֶךְ וּפִיכֹל שַׂר־צְבָאוֹ וַיָּשֻׁבוּ אֶל־אֶרֶץ פְּלִשְׁתִּים׃
וַיִּטַּע אֶשֶׁל בִּבְאֵר שָׁבַע וַיִּקְרָא־שָׁם בְּשֵׁם יְהוָה אֵל עוֹלָם׃
וַיָּגָר אַבְרָהָם בְּאֶרֶץ פְּלִשְׁתִּים יָמִים רַבִּים׃

Chapter 22

וַיְהִי אַחַר הַדְּבָרִים הָאֵלֶּה וְהָאֱלֹהִים נִסָּה אֶת־אַבְרָהָם וַיֹּאמֶר אֵלָיו אַבְרָהָם וַיֹּאמֶר הִנֵּנִי׃
וַיֹּאמֶר קַח־נָא אֶת־בִּנְךָ אֶת־יְחִידְךָ אֲשֶׁר־אָהַבְתָּ אֶת־יִצְחָק וְלֶךְ־לְךָ אֶל־אֶרֶץ הַמֹּרִיָּה וְהַעֲלֵהוּ שָׁם לְעֹלָה עַל אַחַד הֶהָרִים אֲשֶׁר אֹמַר אֵלֶיךָ׃
וַיַּשְׁכֵּם אַבְרָהָם בַּבֹּקֶר וַיַּחֲבֹשׁ אֶת־חֲמֹרוֹ וַיִּקַּח אֶת־שְׁנֵי נְעָרָיו אִתּוֹ וְאֵת יִצְחָק בְּנוֹ וַיְבַקַּע עֲצֵי עֹלָה וַיָּקָם וַיֵּלֶךְ אֶל־הַמָּקוֹם אֲשֶׁר־אָמַר־לוֹ הָאֱלֹהִים׃
בַּיּוֹם הַשְּׁלִישִׁי וַיִּשָּׂא אַבְרָהָם אֶת־עֵינָיו וַיַּרְא אֶת־הַמָּקוֹם מֵרָחֹק׃
וַיֹּאמֶר אַבְרָהָם אֶל־נְעָרָיו שְׁבוּ־לָכֶם פֹּה עִם־הַחֲמוֹר וַאֲנִי וְהַנַּעַר נֵלְכָה עַד־כֹּה וְנִשְׁתַּחֲוֶה וְנָשׁוּבָה אֲלֵיכֶם׃
וַיִּקַּח אַבְרָהָם אֶת־עֲצֵי הָעֹלָה וַיָּשֶׂם עַל־יִצְחָק בְּנוֹ וַיִּקַּח בְּיָדוֹ אֶת־הָאֵשׁ וְאֶת־הַמַּאֲכֶלֶת וַיֵּלְכוּ שְׁנֵיהֶם יַחְדָּו׃
וַיֹּאמֶר יִצְחָק אֶל־אַבְרָהָם אָבִיו וַיֹּאמֶר אָבִי וַיֹּאמֶר הִנֶּנִּי בְנִי וַיֹּאמֶר הִנֵּה הָאֵשׁ וְהָעֵצִים וְאַיֵּה הַשֶּׂה לְעֹלָה׃
וַיֹּאמֶר אַבְרָהָם אֱלֹהִים יִרְאֶה־לּוֹ הַשֶּׂה לְעֹלָה בְּנִי וַיֵּלְכוּ שְׁנֵיהֶם יַחְדָּו׃
וַיָּבֹאוּ אֶל־הַמָּקוֹם אֲשֶׁר אָמַר־לוֹ הָאֱלֹהִים וַיִּבֶן שָׁם אַבְרָהָם אֶת־הַמִּזְבֵּחַ וַיַּעֲרֹךְ אֶת־הָעֵצִים וַיַּעֲקֹד אֶת־יִצְחָק בְּנוֹ וַיָּשֶׂם אֹתוֹ עַל־הַמִּזְבֵּחַ מִמַּעַל לָעֵצִים׃
וַיִּשְׁלַח אַבְרָהָם אֶת־יָדוֹ וַיִּקַּח אֶת־הַמַּאֲכֶלֶת לִשְׁחֹט אֶת־בְּנוֹ׃
וַיִּקְרָא אֵלָיו מַלְאַךְ יְהוָה מִן־הַשָּׁמַיִם וַיֹּאמֶר אַבְרָהָם אַבְרָהָם וַיֹּאמֶר הִנֵּנִי׃
וַיֹּאמֶר אַל־תִּשְׁלַח יָדְךָ אֶל־הַנַּעַר וְאַל־תַּעַשׂ לוֹ מְאוּמָּה כִּי עַתָּה יָדַעְתִּי כִּי־יְרֵא אֱלֹהִים אַתָּה וְלֹא חָשַׂכְתָּ אֶת־בִּנְךָ אֶת־יְחִידְךָ מִמֶּנִּי׃
וַיִּשָּׂא אַבְרָהָם אֶת־עֵינָיו וַיַּרְא וְהִנֵּה־אַיִל אַחַר נֶאֱחַז בַּסְּבַךְ בְּקַרְנָיו וַיֵּלֶךְ אַבְרָהָם וַיִּקַּח אֶת־הָאַיִל וַיַּעֲלֵהוּ לְעֹלָה תַּחַת בְּנוֹ׃
וַיִּקְרָא אַבְרָהָם שֵׁם־הַמָּקוֹם הַהוּא יְהוָה יִרְאֶה אֲשֶׁר יֵאָמֵר הַיּוֹם בְּהַר יְהוָה יֵרָאֶה׃
וַיִּקְרָא מַלְאַךְ יְהוָה אֶל־אַבְרָהָם שֵׁנִית מִן־הַשָּׁמָיִם׃
וַיֹּאמֶר בִּי נִשְׁבַּעְתִּי נְאֻם־יְהוָה כִּי יַעַן אֲשֶׁר עָשִׂיתָ אֶת־הַדָּבָר הַזֶּה וְלֹא חָשַׂכְתָּ אֶת־בִּנְךָ אֶת־יְחִידֶךָ׃
כִּי־בָרֵךְ אֲבָרֶכְךָ וְהַרְבָּה אַרְבֶּה אֶת־זַרְעֲךָ כְּכוֹכְבֵי הַשָּׁמַיִם וְכַחוֹל אֲשֶׁר עַל־שְׂפַת הַיָּם וְיִרַשׁ זַרְעֲךָ אֵת שַׁעַר אֹיְבָיו׃
וְהִתְבָּרֲכוּ בְזַרְעֲךָ כֹּל גּוֹיֵי הָאָרֶץ עֵקֶב אֲשֶׁר שָׁמַעְתָּ בְּקֹלִי׃
וַיָּשָׁב אַבְרָהָם אֶל־נְעָרָיו וַיָּקֻמוּ וַיֵּלְכוּ יַחְדָּו אֶל־בְּאֵר שָׁבַע וַיֵּשֶׁב אַבְרָהָם בִּבְאֵר שָׁבַע׃
וַיְהִי אַחֲרֵי הַדְּבָרִים הָאֵלֶּה וַיֻּגַּד לְאַבְרָהָם לֵאמֹר הִנֵּה יָלְדָה מִלְכָּה גַם־הִוא בָּנִים לְנָחוֹר אָחִיךָ׃
אֶת־עוּץ בְּכֹרוֹ וְאֶת־בּוּז אָחִיו וְאֶת־קְמוּאֵל אֲבִי אֲרָם׃
וְאֶת־כֶּשֶׂד וְאֶת־חֲזוֹ וְאֶת־פִּלְדָּשׁ וְאֶת־יִדְלָף וְאֵת בְּתוּאֵל׃
וּבְתוּאֵל יָלַד אֶת־רִבְקָה שְׁמֹנָה אֵלֶּה יָלְדָה מִלְכָּה לְנָחוֹר אֲחִי אַבְרָהָם׃
וּפִילַגְשׁוֹ וּשְׁמָהּ רְאוּמָה וַתֵּלֶד גַּם־הִוא אֶת־טֶבַח וְאֶת־גַּחַם וְאֶת־תַּחַשׁ וְאֶת־מַעֲכָה׃

Chapter 23

וַיִּהְיוּ חַיֵּי שָׂרָה מֵאָה שָׁנָה וְעֶשְׂרִים שָׁנָה וְשֶׁבַע שָׁנִים שְׁנֵי חַיֵּי שָׂרָה׃
וַתָּמָת שָׂרָה בְּקִרְיַת אַרְבַּע הִוא חֶבְרוֹן בְּאֶרֶץ כְּנָעַן וַיָּבֹא אַבְרָהָם לִסְפֹּד לְשָׂרָה וְלִבְכֹּתָהּ׃
וַיָּקָם אַבְרָהָם מֵעַל פְּנֵי מֵתוֹ וַיְדַבֵּר אֶל־בְּנֵי־חֵת לֵאמֹר׃
גֵּר־וְתוֹשָׁב אָנֹכִי עִמָּכֶם תְּנוּ לִי אֲחֻזַּת־קֶבֶר עִמָּכֶם וְאֶקְבְּרָה מֵתִי מִלְּפָנָי׃
וַיַּעֲנוּ בְנֵי־חֵת אֶת־אַבְרָהָם לֵאמֹר לוֹ׃
שְׁמָעֵנוּ אֲדֹנִי נְשִׂיא אֱלֹהִים אַתָּה בְּתוֹכֵנוּ בְּמִבְחַר קְבָרֵינוּ קְבֹר אֶת־מֵתֶךָ אִישׁ מִמֶּנּוּ אֶת־קִבְרוֹ לֹא־יִכְלֶה מִמְּךָ מִקְּבֹר מֵתֶךָ׃
וַיָּקָם אַבְרָהָם וַיִּשְׁתַּחוּ לְעַם־הָאָרֶץ לִבְנֵי־חֵת׃
וַיְדַבֵּר אִתָּם לֵאמֹר אִם־יֵשׁ אֶת־נַפְשְׁכֶם לִקְבֹּר אֶת־מֵתִי מִלְּפָנַי שְׁמָעוּנִי וּפִגְעוּ־לִי בְּעֶפְרוֹן בֶּן־צֹחַר׃
וְיִתֶּן־לִי אֶת־מְעָרַת הַמַּכְפֵּלָה אֲשֶׁר־לוֹ אֲשֶׁר בִּקְצֵה שָׂדֵהוּ בְּכֶסֶף מָלֵא יִתְּנֶנָּה לִי בְּתוֹכְכֶם לַאֲחֻזַּת־קָבֶר׃
וְעֶפְרוֹן יֹשֵׁב בְּתוֹךְ בְּנֵי־חֵת וַיַּעַן עֶפְרוֹן הַחִתִּי אֶת־אַבְרָהָם בְּאָזְנֵי בְנֵי־חֵת לְכֹל בָּאֵי שַׁעַר־עִירוֹ לֵאמֹר׃
לֹא־אֲדֹנִי שְׁמָעֵנִי הַשָּׂדֶה נָתַתִּי לָךְ וְהַמְּעָרָה אֲשֶׁר־בּוֹ לְךָ נְתַתִּיהָ לְעֵינֵי בְנֵי־עַמִּי נְתַתִּיהָ לָּךְ קְבֹר מֵתֶךָ׃
וַיִּשְׁתַּחוּ אַבְרָהָם לִפְנֵי עַם הָאָרֶץ׃
וַיְדַבֵּר אֶל־עֶפְרוֹן בְּאָזְנֵי עַם־הָאָרֶץ לֵאמֹר אַךְ אִם־אַתָּה לוּ שְׁמָעֵנִי נָתַתִּי כֶּסֶף הַשָּׂדֶה קַח מִמֶּנִּי וְאֶקְבְּרָה אֶת־מֵתִי שָׁמָּה׃
וַיַּעַן עֶפְרוֹן אֶת־אַבְרָהָם לֵאמֹר לוֹ׃
אֲדֹנִי שְׁמָעֵנִי אֶרֶץ אַרְבַּע מֵאֹת שֶׁקֶל־כֶּסֶף בֵּינִי וּבֵינְךָ מַה־הִוא וְאֶת־מֵתְךָ קְבֹר׃
וַיִּשְׁמַע אַבְרָהָם אֶל־עֶפְרוֹן וַיִּשְׁקֹל אַבְרָהָם לְעֶפְרֹן אֶת־הַכֶּסֶף אֲשֶׁר דִּבֶּר בְּאָזְנֵי בְנֵי־חֵת אַרְבַּע מֵאוֹת שֶׁקֶל כֶּסֶף עֹבֵר לַסֹּחֵר׃
וַיָּקָם שְׂדֵה עֶפְרוֹן אֲשֶׁר בַּמַּכְפֵּלָה אֲשֶׁר לִפְנֵי מַמְרֵא הַשָּׂדֶה וְהַמְּעָרָה אֲשֶׁר־בּוֹ וְכָל־הָעֵץ אֲשֶׁר בַּשָּׂדֶה אֲשֶׁר בְּכָל־גְּבֻלוֹ סָבִיב׃
לְאַבְרָהָם לְמִקְנָה לְעֵינֵי בְנֵי־חֵת בְּכֹל בָּאֵי שַׁעַר־עִירוֹ׃
וְאַחֲרֵי־כֵן קָבַר אַבְרָהָם אֶת־שָׂרָה אִשְׁתּוֹ אֶל־מְעָרַת שְׂדֵה הַמַּכְפֵּלָה עַל־פְּנֵי מַמְרֵא הִוא חֶבְרוֹן בְּאֶרֶץ כְּנָעַן׃
וַיָּקָם הַשָּׂדֶה וְהַמְּעָרָה אֲשֶׁר־בּוֹ לְאַבְרָהָם לַאֲחֻזַּת־קָבֶר מֵאֵת בְּנֵי־חֵת׃

Chapter 24

וְאַבְרָהָם זָקֵן בָּא בַּיָּמִים וַיהוָה בֵּרַךְ אֶת־אַבְרָהָם בַּכֹּל׃
וַיֹּאמֶר אַבְרָהָם אֶל־עַבְדּוֹ זְקַן בֵּיתוֹ הַמֹּשֵׁל בְּכָל־אֲשֶׁר־לוֹ שִׂים־נָא יָדְךָ תַּחַת יְרֵכִי׃
וְאַשְׁבִּיעֲךָ בַּיהוָה אֱלֹהֵי הַשָּׁמַיִם וֵאלֹהֵי הָאָרֶץ אֲשֶׁר לֹא־תִקַּח אִשָּׁה לִבְנִי מִבְּנוֹת הַכְּנַעֲנִי אֲשֶׁר אָנֹכִי יוֹשֵׁב בְּקִרְבּוֹ׃
כִּי אֶל־אַרְצִי וְאֶל־מוֹלַדְתִּי תֵּלֵךְ וְלָקַחְתָּ אִשָּׁה לִבְנִי לְיִצְחָק׃
וַיֹּאמֶר אֵלָיו הָעֶבֶד אוּלַי לֹא־תֹאבֶה הָאִשָּׁה לָלֶכֶת אַחֲרַי אֶל־הָאָרֶץ הַזֹּאת הֶהָשֵׁב אָשִׁיב אֶת־בִּנְךָ אֶל־הָאָרֶץ אֲשֶׁר־יָצָאתָ מִשָּׁם׃
וַיֹּאמֶר אֵלָיו אַבְרָהָם הִשָּׁמֶר לְךָ פֶּן־תָּשִׁיב אֶת־בְּנִי שָׁמָּה׃
יְהוָה אֱלֹהֵי הַשָּׁמַיִם אֲשֶׁר לְקָחַנִי מִבֵּית אָבִי וּמֵאֶרֶץ מוֹלַדְתִּי וַאֲשֶׁר דִּבֶּר־לִי וַאֲשֶׁר נִשְׁבַּע־לִי לֵאמֹר לְזַרְעֲךָ אֶתֵּן אֶת־הָאָרֶץ הַזֹּאת הוּא יִשְׁלַח מַלְאָכוֹ לְפָנֶיךָ וְלָקַחְתָּ אִשָּׁה לִבְנִי מִשָּׁם׃
וְאִם־לֹא תֹאבֶה הָאִשָּׁה לָלֶכֶת אַחֲרֶיךָ וְנִקִּיתָ מִשְּׁבֻעָתִי זֹאת רַק אֶת־בְּנִי לֹא תָשֵׁב שָׁמָּה׃
וַיָּשֶׂם הָעֶבֶד אֶת־יָדוֹ תַּחַת יֶרֶךְ אַבְרָהָם אֲדֹנָיו וַיִּשָּׁבַע לוֹ עַל־הַדָּבָר הַזֶּה׃
וַיִּקַּח הָעֶבֶד עֲשָׂרָה גְמַלִּים מִגְּמַלֵּי אֲדֹנָיו וַיֵּלֶךְ וְכָל־טוּב אֲדֹנָיו בְּיָדוֹ וַיָּקָם וַיֵּלֶךְ אֶל־אֲרַם נַהֲרַיִם אֶל־עִיר נָחוֹר׃
וַיַּבְרֵךְ הַגְּמַלִּים מִחוּץ לָעִיר אֶל־בְּאֵר הַמָּיִם לְעֵת עֶרֶב לְעֵת צֵאת הַשֹּׁאֲבֹת׃
וַיֹּאמַר יְהוָה אֱלֹהֵי אֲדֹנִי אַבְרָהָם הַקְרֵה־נָא לְפָנַי הַיּוֹם וַעֲשֵׂה־חֶסֶד עִם אֲדֹנִי אַבְרָהָם׃
הִנֵּה אָנֹכִי נִצָּב עַל־עֵין הַמָּיִם וּבְנוֹת אַנְשֵׁי הָעִיר יֹצְאֹת לִשְׁאֹב מָיִם׃
וְהָיָה הַנַּעֲרָ אֲשֶׁר אֹמַר אֵלֶיהָ הַטִּי־נָא כַדֵּךְ וְאֶשְׁתֶּה וְאָמְרָה שְׁתֵה וְגַם־גְּמַלֶּיךָ אַשְׁקֶה אֹתָהּ הֹכַחְתָּ לְעַבְדְּךָ לְיִצְחָק וּבָהּ אֵדַע כִּי־עָשִׂיתָ חֶסֶד עִם־אֲדֹנִי׃
וַיְהִי־הוּא טֶרֶם כִּלָּה לְדַבֵּר וְהִנֵּה רִבְקָה יֹצֵאת אֲשֶׁר יֻלְּדָה לִבְתוּאֵל בֶּן־מִלְכָּה אֵשֶׁת נָחוֹר אֲחִי אַבְרָהָם וְכַדָּהּ עַל־שִׁכְמָהּ׃
וְהַנַּעֲרָ טֹבַת מַרְאֶה מְאֹד בְּתוּלָה וְאִישׁ לֹא יְדָעָהּ וַתֵּרֶד הָעַיְנָה וַתְּמַלֵּא כַדָּהּ וַתָּעַל׃
וַיָּרָץ הָעֶבֶד לִקְרָאתָהּ וַיֹּאמֶר הַגְמִיאִינִי נָא מְעַט־מַיִם מִכַּדֵּךְ׃
וַתֹּאמֶר שְׁתֵה אֲדֹנִי וַתְּמַהֵר וַתֹּרֶד כַּדָּהּ עַל־יָדָהּ וַתַּשְׁקֵהוּ׃
וַתְּכַל לְהַשְׁקֹתוֹ וַתֹּאמֶר גַּם לִגְמַלֶּיךָ אֶשְׁאָב עַד אִם־כִּלּוּ לִשְׁתֹּת׃
וַתְּמַהֵר וַתְּעַר כַּדָּהּ אֶל־הַשֹּׁקֶת וַתָּרָץ עוֹד אֶל־הַבְּאֵר לִשְׁאֹב וַתִּשְׁאַב לְכָל־גְּמַלָּיו׃
וְהָאִישׁ מִשְׁתָּאֵה לָהּ מַחֲרִישׁ לָדַעַת הַהִצְלִיחַ יְהוָה דַּרְכּוֹ אִם־לֹא׃
וַיְהִי כַּאֲשֶׁר כִּלּוּ הַגְּמַלִּים לִשְׁתּוֹת וַיִּקַּח הָאִישׁ נֶזֶם זָהָב בֶּקַע מִשְׁקָלוֹ וּשְׁנֵי צְמִידִים עַל־יָדֶיהָ עֲשָׂרָה זָהָב מִשְׁקָלָם׃
וַיֹּאמֶר בַּת־מִי אַתְּ הַגִּידִי נָא לִי הֲיֵשׁ בֵּית־אָבִיךְ מָקוֹם לָנוּ לָלִין׃
וַתֹּאמֶר אֵלָיו בַּת־בְּתוּאֵל אָנֹכִי בֶּן־מִלְכָּה אֲשֶׁר יָלְדָה לְנָחוֹר׃
וַתֹּאמֶר אֵלָיו גַּם־תֶּבֶן גַּם־מִסְפּוֹא רַב עִמָּנוּ גַּם־מָקוֹם לָלוּן׃
וַיִּקֹּד הָאִישׁ וַיִּשְׁתַּחוּ לַיהוָה׃
וַיֹּאמֶר בָּרוּךְ יְהוָה אֱלֹהֵי אֲדֹנִי אַבְרָהָם אֲשֶׁר לֹא־עָזַב חַסְדּוֹ וַאֲמִתּוֹ מֵעִם אֲדֹנִי אָנֹכִי בַּדֶּרֶךְ נָחַנִי יְהוָה בֵּית אֲחֵי אֲדֹנִי׃
וַתָּרָץ הַנַּעֲרָ וַתַּגֵּד לְבֵית אִמָּהּ כַּדְּבָרִים הָאֵלֶּה׃
וּלְרִבְקָה אָח וּשְׁמוֹ לָבָן וַיָּרָץ לָבָן אֶל־הָאִישׁ הַחוּצָה אֶל־הָעָיִן׃
וַיְהִי כִּרְאֹת אֶת־הַנֶּזֶם וְאֶת־הַצְּמִדִים עַל־יְדֵי אֲחֹתוֹ וּכְשָׁמְעוֹ אֶת־דִּבְרֵי רִבְקָה אֲחֹתוֹ לֵאמֹר כֹּה־דִבֶּר אֵלַי הָאִישׁ וַיָּבֹא אֶל־הָאִישׁ וְהִנֵּה עֹמֵד עַל־הַגְּמַלִּים עַל־הָעָיִן׃
וַיֹּאמֶר בּוֹא בְּרוּךְ יְהוָה לָמָּה תַעֲמֹד בַּחוּץ וְאָנֹכִי פִּנִּיתִי הַבַּיִת וּמָקוֹם לַגְּמַלִּים׃
וַיָּבֹא הָאִישׁ הַבַּיְתָה וַיְפַתַּח הַגְּמַלִּים וַיִּתֵּן תֶּבֶן וּמִסְפּוֹא לַגְּמַלִּים וּמַיִם לִרְחֹץ רַגְלָיו וְרַגְלֵי הָאֲנָשִׁים אֲשֶׁר אִתּוֹ׃
ויישם [וַיּוּשַׂם] לְפָנָיו לֶאֱכֹל וַיֹּאמֶר לֹא אֹכַל עַד אִם־דִּבַּרְתִּי דְּבָרָי וַיֹּאמֶר דַּבֵּר׃
וַיֹּאמַר עֶבֶד אַבְרָהָם אָנֹכִי׃
וַיהוָה בֵּרַךְ אֶת־אֲדֹנִי מְאֹד וַיִּגְדָּל וַיִּתֶּן־לוֹ צֹאן וּבָקָר וְכֶסֶף וְזָהָב וַעֲבָדִם וּשְׁפָחֹת וּגְמַלִּים וַחֲמֹרִים׃
וַתֵּלֶד שָׂרָה אֵשֶׁת אֲדֹנִי בֵן לַאדֹנִי אַחֲרֵי זִקְנָתָהּ וַיִּתֶּן־לּוֹ אֶת־כָּל־אֲשֶׁר־לוֹ׃
וַיַּשְׁבִּעֵנִי אֲדֹנִי לֵאמֹר לֹא־תִקַּח אִשָּׁה לִבְנִי מִבְּנוֹת הַכְּנַעֲנִי אֲשֶׁר אָנֹכִי יֹשֵׁב בְּאַרְצוֹ׃
אִם־לֹא אֶל־בֵּית־אָבִי תֵּלֵךְ וְאֶל־מִשְׁפַּחְתִּי וְלָקַחְתָּ אִשָּׁה לִבְנִי׃
וָאֹמַר אֶל־אֲדֹנִי אֻלַי לֹא־תֵלֵךְ הָאִשָּׁה אַחֲרָי׃
וַיֹּאמֶר אֵלָי יְהוָה אֲשֶׁר־הִתְהַלַּכְתִּי לְפָנָיו יִשְׁלַח מַלְאָכוֹ אִתָּךְ וְהִצְלִיחַ דַּרְכֶּךָ וְלָקַחְתָּ אִשָּׁה לִבְנִי מִמִּשְׁפַּחְתִּי וּמִבֵּית אָבִי׃
אָז תִּנָּקֶה מֵאָלָתִי כִּי תָבוֹא אֶל־מִשְׁפַּחְתִּי וְאִם־לֹא יִתְּנוּ לָךְ וְהָיִיתָ נָקִי מֵאָלָתִי׃
וָאָבֹא הַיּוֹם אֶל־הָעָיִן וָאֹמַר יְהוָה אֱלֹהֵי אֲדֹנִי אַבְרָהָם אִם־יֶשְׁךָ־נָּא מַצְלִיחַ דַּרְכִּי אֲשֶׁר אָנֹכִי הֹלֵךְ עָלֶיהָ׃
הִנֵּה אָנֹכִי נִצָּב עַל־עֵין הַמָּיִם וְהָיָה הָעַלְמָה הַיֹּצֵאת לִשְׁאֹב וְאָמַרְתִּי אֵלֶיהָ הַשְׁקִינִי־נָא מְעַט־מַיִם מִכַּדֵּךְ׃
וְאָמְרָה אֵלַי גַּם־אַתָּה שְׁתֵה וְגַם לִגְמַלֶּיךָ אֶשְׁאָב הִוא הָאִשָּׁה אֲשֶׁר־הֹכִיחַ יְהוָה לְבֶן־אֲדֹנִי׃
אֲנִי טֶרֶם אֲכַלֶּה לְדַבֵּר אֶל־לִבִּי וְהִנֵּה רִבְקָה יֹצֵאת וְכַדָּהּ עַל־שִׁכְמָהּ וַתֵּרֶד הָעַיְנָה וַתִּשְׁאָב וָאֹמַר אֵלֶיהָ הַשְׁקִינִי נָא׃
וַתְּמַהֵר וַתּוֹרֶד כַּדָּהּ מֵעָלֶיהָ וַתֹּאמֶר שְׁתֵה וְגַם־גְּמַלֶּיךָ אַשְׁקֶה וָאֵשְׁתְּ וְגַם הַגְּמַלִּים הִשְׁקָתָה׃
וָאֶשְׁאַל אֹתָהּ וָאֹמַר בַּת־מִי אַתְּ וַתֹּאמֶר בַּת־בְּתוּאֵל בֶּן־נָחוֹר אֲשֶׁר יָלְדָה־לּוֹ מִלְכָּה וָאָשִׂם הַנֶּזֶם עַל־אַפָּהּ וְהַצְּמִידִים עַל־יָדֶיהָ׃
וָאֶקֹּד וָאֶשְׁתַּחֲוֶה לַיהוָה וָאֲבָרֵךְ אֶת־יְהוָה אֱלֹהֵי אֲדֹנִי אַבְרָהָם אֲשֶׁר הִנְחַנִי בְּדֶרֶךְ אֱמֶת לָקַחַת אֶת־בַּת־אֲחִי אֲדֹנִי לִבְנוֹ׃
וְעַתָּה אִם־יֶשְׁכֶם עֹשִׂים חֶסֶד וֶאֱמֶת אֶת־אֲדֹנִי הַגִּידוּ לִי וְאִם־לֹא הַגִּידוּ לִי וְאֶפְנֶה עַל־יָמִין אוֹ עַל־שְׂמֹאל׃
וַיַּעַן לָבָן וּבְתוּאֵל וַיֹּאמְרוּ מֵיְהוָה יָצָא הַדָּבָר לֹא נוּכַל דַּבֵּר אֵלֶיךָ רַע אוֹ־טוֹב׃
הִנֵּה־רִבְקָה לְפָנֶיךָ קַח וָלֵךְ וּתְהִי אִשָּׁה לְבֶן־אֲדֹנֶיךָ כַּאֲשֶׁר דִּבֶּר יְהוָה׃
וַיְהִי כַּאֲשֶׁר שָׁמַע עֶבֶד אַבְרָהָם אֶת־דִּבְרֵיהֶם וַיִּשְׁתַּחוּ אַרְצָה לַיהוָה׃
וַיּוֹצֵא הָעֶבֶד כְּלֵי־כֶסֶף וּכְלֵי זָהָב וּבְגָדִים וַיִּתֵּן לְרִבְקָה וּמִגְדָּנֹת נָתַן לְאָחִיהָ וּלְאִמָּהּ׃
וַיֹּאכְלוּ וַיִּשְׁתּוּ הוּא וְהָאֲנָשִׁים אֲשֶׁר־עִמּוֹ וַיָּלִינוּ וַיָּקוּמוּ בַבֹּקֶר וַיֹּאמֶר שַׁלְּחֻנִי לַאדֹנִי׃
וַיֹּאמֶר אָחִיהָ וְאִמָּהּ תֵּשֵׁב הַנַּעֲרָ אִתָּנוּ יָמִים אוֹ עָשׂוֹר אַחַר תֵּלֵךְ׃
וַיֹּאמֶר אֲלֵהֶם אַל־תְּאַחֲרוּ אֹתִי וַיהוָה הִצְלִיחַ דַּרְכִּי שַׁלְּחוּנִי וְאֵלְכָה לַאדֹנִי׃
וַיֹּאמְרוּ נִקְרָא לַנַּעֲרָ וְנִשְׁאֲלָה אֶת־פִּיהָ׃
וַיִּקְרְאוּ לְרִבְקָה וַיֹּאמְרוּ אֵלֶיהָ הֲתֵלְכִי עִם־הָאִישׁ הַזֶּה וַתֹּאמֶר אֵלֵךְ׃
וַיְשַׁלְּחוּ אֶת־רִבְקָה אֲחֹתָם וְאֶת־מֵנִקְתָּהּ וְאֶת־עֶבֶד אַבְרָהָם וְאֶת־אֲנָשָׁיו׃
וַיְבָרֲכוּ אֶת־רִבְקָה וַיֹּאמְרוּ לָהּ אֲחֹתֵנוּ אַתְּ הֲיִי לְאַלְפֵי רְבָבָה וְיִירַשׁ זַרְעֵךְ אֵת שַׁעַר שֹׂנְאָיו׃
וַתָּקָם רִבְקָה וְנַעֲרֹתֶיהָ וַתִּרְכַּבְנָה עַל־הַגְּמַלִּים וַתֵּלַכְנָה אַחֲרֵי הָאִישׁ וַיִּקַּח הָעֶבֶד אֶת־רִבְקָה וַיֵּלַךְ׃
וְיִצְחָק בָּא מִבּוֹא בְּאֵר לַחַי רֹאִי וְהוּא יוֹשֵׁב בְּאֶרֶץ הַנֶּגֶב׃
וַיֵּצֵא יִצְחָק לָשׂוּחַ בַּשָּׂדֶה לִפְנוֹת עָרֶב וַיִּשָּׂא עֵינָיו וַיַּרְא וְהִנֵּה גְמַלִּים בָּאִים׃
וַתִּשָּׂא רִבְקָה אֶת־עֵינֶיהָ וַתֵּרֶא אֶת־יִצְחָק וַתִּפֹּל מֵעַל הַגָּמָל׃
וַתֹּאמֶר אֶל־הָעֶבֶד מִי־הָאִישׁ הַלָּזֶה הַהֹלֵךְ בַּשָּׂדֶה לִקְרָאתֵנוּ וַיֹּאמֶר הָעֶבֶד הוּא אֲדֹנִי וַתִּקַּח הַצָּעִיף וַתִּתְכָּס׃
וַיְסַפֵּר הָעֶבֶד לְיִצְחָק אֵת כָּל־הַדְּבָרִים אֲשֶׁר עָשָׂה׃
וַיְבִאֶהָ יִצְחָק הָאֹהֱלָה שָׂרָה אִמּוֹ וַיִּקַּח אֶת־רִבְקָה וַתְּהִי־לוֹ לְאִשָּׁה וַיֶּאֱהָבֶהָ וַיִּנָּחֵם יִצְחָק אַחֲרֵי אִמּוֹ׃

Chapter 25

וַיֹּסֶף אַבְרָהָם וַיִּקַּח אִשָּׁה וּשְׁמָהּ קְטוּרָה׃
וַתֵּלֶד לוֹ אֶת־זִמְרָן וְאֶת־יָקְשָׁן וְאֶת־מְדָן וְאֶת־מִדְיָן וְאֶת־יִשְׁבָּק וְאֶת־שׁוּחַ׃
וְיָקְשָׁן יָלַד אֶת־שְׁבָא וְאֶת־דְּדָן וּבְנֵי דְדָן הָיוּ אַשּׁוּרִם וּלְטוּשִׁים וּלְאֻמִּים׃
וּבְנֵי מִדְיָן עֵיפָה וָעֵפֶר וַחֲנֹךְ וַאֲבִידָע וְאֶלְדָּעָה כָּל־אֵלֶּה בְּנֵי קְטוּרָה׃
וַיִּתֵּן אַבְרָהָם אֶת־כָּל־אֲשֶׁר־לוֹ לְיִצְחָק׃
וְלִבְנֵי הַפִּילַגְשִׁים אֲשֶׁר לְאַבְרָהָם נָתַן אַבְרָהָם מַתָּנֹת וַיְשַׁלְּחֵם מֵעַל יִצְחָק בְּנוֹ בְּעוֹדֶנּוּ חַי קֵדְמָה אֶל־אֶרֶץ קֶדֶם׃
וְאֵלֶּה יְמֵי שְׁנֵי־חַיֵּי אַבְרָהָם אֲשֶׁר־חָי מְאַת שָׁנָה וְשִׁבְעִים שָׁנָה וְחָמֵשׁ שָׁנִים׃
וַיִּגְוַע וַיָּמָת אַבְרָהָם בְּשֵׂיבָה טוֹבָה זָקֵן וְשָׂבֵעַ וַיֵּאָסֶף אֶל־עַמָּיו׃
וַיִּקְבְּרוּ אֹתוֹ יִצְחָק וְיִשְׁמָעֵאל בָּנָיו אֶל־מְעָרַת הַמַּכְפֵּלָה אֶל־שְׂדֵה עֶפְרֹן בֶּן־צֹחַר הַחִתִּי אֲשֶׁר עַל־פְּנֵי מַמְרֵא׃
הַשָּׂדֶה אֲשֶׁר־קָנָה אַבְרָהָם מֵאֵת בְּנֵי־חֵת שָׁמָּה קֻבַּר אַבְרָהָם וְשָׂרָה אִשְׁתּוֹ׃
וַיְהִי אַחֲרֵי מוֹת אַבְרָהָם וַיְבָרֶךְ אֱלֹהִים אֶת־יִצְחָק בְּנוֹ וַיֵּשֶׁב יִצְחָק עִם־בְּאֵר לַחַי רֹאִי׃
וְאֵלֶּה תֹּלְדֹת יִשְׁמָעֵאל בֶּן־אַבְרָהָם אֲשֶׁר יָלְדָה הָגָר הַמִּצְרִית שִׁפְחַת שָׂרָה לְאַבְרָהָם׃
וְאֵלֶּה שְׁמוֹת בְּנֵי יִשְׁמָעֵאל בִּשְׁמֹתָם לְתוֹלְדֹתָם בְּכֹר יִשְׁמָעֵאל נְבָיֹת וְקֵדָר וְאַדְבְּאֵל וּמִבְשָׂם׃
וּמִשְׁמָע וְדוּמָה וּמַשָּׂא׃
חֲדַד וְתֵימָא יְטוּר נָפִישׁ וָקֵדְמָה׃
אֵלֶּה הֵם בְּנֵי יִשְׁמָעֵאל וְאֵלֶּה שְׁמֹתָם בְּחַצְרֵיהֶם וּבְטִירֹתָם שְׁנֵים־עָשָׂר נְשִׂיאִם לְאֻמֹּתָם׃
וְאֵלֶּה שְׁנֵי חַיֵּי יִשְׁמָעֵאל מְאַת שָׁנָה וּשְׁלֹשִׁים שָׁנָה וְשֶׁבַע שָׁנִים וַיִּגְוַע וַיָּמָת וַיֵּאָסֶף אֶל־עַמָּיו׃
וַיִּשְׁכְּנוּ מֵחֲוִילָה עַד־שׁוּר אֲשֶׁר עַל־פְּנֵי מִצְרַיִם בֹּאֲכָה אַשּׁוּרָה עַל־פְּנֵי כָל־אֶחָיו נָפָל׃
וְאֵלֶּה תּוֹלְדֹת יִצְחָק בֶּן־אַבְרָהָם אַבְרָהָם הוֹלִיד אֶת־יִצְחָק׃
וַיְהִי יִצְחָק בֶּן־אַרְבָּעִים שָׁנָה בְּקַחְתּוֹ אֶת־רִבְקָה בַּת־בְּתוּאֵל הָאֲרַמִּי מִפַּדַּן אֲרָם אֲחוֹת לָבָן הָאֲרַמִּי לוֹ לְאִשָּׁה׃
וַיֶּעְתַּר יִצְחָק לַיהוָה לְנֹכַח אִשְׁתּוֹ כִּי עֲקָרָה הִוא וַיֵּעָתֶר לוֹ יְהוָה וַתַּהַר רִבְקָה אִשְׁתּוֹ׃
וַיִּתְרֹצֲצוּ הַבָּנִים בְּקִרְבָּהּ וַתֹּאמֶר אִם־כֵּן לָמָּה זֶּה אָנֹכִי וַתֵּלֶךְ לִדְרֹשׁ אֶת־יְהוָה׃
וַיֹּאמֶר יְהוָה לָהּ שְׁנֵי גיים [גוֹיִם] בְּבִטְנֵךְ וּשְׁנֵי לְאֻמִּים מִמֵּעַיִךְ יִפָּרֵדוּ וּלְאֹם מִלְאֹם יֶאֱמָץ וְרַב יַעֲבֹד צָעִיר׃
וַיִּמְלְאוּ יָמֶיהָ לָלֶדֶת וְהִנֵּה תוֹמִם בְּבִטְנָהּ׃
וַיֵּצֵא הָרִאשׁוֹן אַדְמוֹנִי כֻּלּוֹ כְּאַדֶּרֶת שֵׂעָר וַיִּקְרְאוּ שְׁמוֹ עֵשָׂו׃
וְאַחֲרֵי־כֵן יָצָא אָחִיו וְיָדוֹ אֹחֶזֶת בַּעֲקֵב עֵשָׂו וַיִּקְרָא שְׁמוֹ יַעֲקֹב וְיִצְחָק בֶּן־שִׁשִּׁים שָׁנָה בְּלֶדֶת אֹתָם׃
וַיִּגְדְּלוּ הַנְּעָרִים וַיְהִי עֵשָׂו אִישׁ יֹדֵעַ צַיִד אִישׁ שָׂדֶה וְיַעֲקֹב אִישׁ תָּם יֹשֵׁב אֹהָלִים׃
וַיֶּאֱהַב יִצְחָק אֶת־עֵשָׂו כִּי־צַיִד בְּפִיו וְרִבְקָה אֹהֶבֶת אֶת־יַעֲקֹב׃
וַיָּזֶד יַעֲקֹב נָזִיד וַיָּבֹא עֵשָׂו מִן־הַשָּׂדֶה וְהוּא עָיֵף׃
וַיֹּאמֶר עֵשָׂו אֶל־יַעֲקֹב הַלְעִיטֵנִי נָא מִן־הָאָדֹם הָאָדֹם הַזֶּה כִּי עָיֵף אָנֹכִי עַל־כֵּן קָרָא־שְׁמוֹ אֱדוֹם׃
וַיֹּאמֶר יַעֲקֹב מִכְרָה כַיּוֹם אֶת־בְּכֹרָתְךָ לִי׃
וַיֹּאמֶר עֵשָׂו הִנֵּה אָנֹכִי הוֹלֵךְ לָמוּת וְלָמָּה־זֶּה לִי בְּכֹרָה׃
וַיֹּאמֶר יַעֲקֹב הִשָּׁבְעָה לִּי כַּיּוֹם וַיִּשָּׁבַע לוֹ וַיִּמְכֹּר אֶת־בְּכֹרָתוֹ לְיַעֲקֹב׃
וְיַעֲקֹב נָתַן לְעֵשָׂו לֶחֶם וּנְזִיד עֲדָשִׁים וַיֹּאכַל וַיֵּשְׁתְּ וַיָּקָם וַיֵּלַךְ וַיִּבֶז עֵשָׂו אֶת־הַבְּכֹרָה׃

Chapter 26

וַיְהִי רָעָב בָּאָרֶץ מִלְּבַד הָרָעָב הָרִאשׁוֹן אֲשֶׁר הָיָה בִּימֵי אַבְרָהָם וַיֵּלֶךְ יִצְחָק אֶל־אֲבִימֶּלֶךְ מֶלֶךְ־פְּלִשְׁתִּים גְּרָרָה׃
וַיֵּרָא אֵלָיו יְהוָה וַיֹּאמֶר אַל־תֵּרֵד מִצְרָיְמָה שְׁכֹן בָּאָרֶץ אֲשֶׁר אֹמַר אֵלֶיךָ׃
גּוּר בָּאָרֶץ הַזֹּאת וְאֶהְיֶה עִמְּךָ וַאֲבָרְכֶךָּ כִּי־לְךָ וּלְזַרְעֲךָ אֶתֵּן אֶת־כָּל־הָאֲרָצֹת הָאֵל וַהֲקִמֹתִי אֶת־הַשְּׁבֻעָה אֲשֶׁר נִשְׁבַּעְתִּי לְאַבְרָהָם אָבִיךָ׃
וְהִרְבֵּיתִי אֶת־זַרְעֲךָ כְּכוֹכְבֵי הַשָּׁמַיִם וְנָתַתִּי לְזַרְעֲךָ אֵת כָּל־הָאֲרָצֹת הָאֵל וְהִתְבָּרֲכוּ בְזַרְעֲךָ כֹּל גּוֹיֵי הָאָרֶץ׃
עֵקֶב אֲשֶׁר־שָׁמַע אַבְרָהָם בְּקֹלִי וַיִּשְׁמֹר מִשְׁמַרְתִּי מִצְוֺתַי חֻקּוֹתַי וְתוֹרֹתָי׃
וַיֵּשֶׁב יִצְחָק בִּגְרָר׃
וַיִּשְׁאֲלוּ אַנְשֵׁי הַמָּקוֹם לְאִשְׁתּוֹ וַיֹּאמֶר אֲחֹתִי הִוא כִּי יָרֵא לֵאמֹר אִשְׁתִּי פֶּן־יַהַרְגֻנִי אַנְשֵׁי הַמָּקוֹם עַל־רִבְקָה כִּי־טוֹבַת מַרְאֶה הִיא׃
וַיְהִי כִּי אָרְכוּ־לוֹ שָׁם הַיָּמִים וַיַּשְׁקֵף אֲבִימֶלֶךְ מֶלֶךְ פְּלִשְׁתִּים בְּעַד הַחַלּוֹן וַיַּרְא וְהִנֵּה יִצְחָק מְצַחֵק אֵת רִבְקָה אִשְׁתּוֹ׃
וַיִּקְרָא אֲבִימֶלֶךְ לְיִצְחָק וַיֹּאמֶר אַךְ הִנֵּה אִשְׁתְּךָ הִוא וְאֵיךְ אָמַרְתָּ אֲחֹתִי הִוא וַיֹּאמֶר אֵלָיו יִצְחָק כִּי אָמַרְתִּי פֶּן־אָמוּת עָלֶיהָ׃
וַיֹּאמֶר אֲבִימֶלֶךְ מַה־זֹּאת עָשִׂיתָ לָּנוּ כִּמְעַט שָׁכַב אַחַד הָעָם אֶת־אִשְׁתֶּךָ וְהֵבֵאתָ עָלֵינוּ אָשָׁם׃
וַיְצַו אֲבִימֶלֶךְ אֶת־כָּל־הָעָם לֵאמֹר הַנֹּגֵעַ בָּאִישׁ הַזֶּה וּבְאִשְׁתּוֹ מוֹת יוּמָת׃
וַיִּזְרַע יִצְחָק בָּאָרֶץ הַהִוא וַיִּמְצָא בַּשָּׁנָה הַהִוא מֵאָה שְׁעָרִים וַיְבָרֲכֵהוּ יְהוָה׃
וַיִּגְדַּל הָאִישׁ וַיֵּלֶךְ הָלוֹךְ וְגָדֵל עַד כִּי־גָדַל מְאֹד׃
וַיְהִי־לוֹ מִקְנֵה־צֹאן וּמִקְנֵה בָקָר וַעֲבֻדָּה רַבָּה וַיְקַנְאוּ אֹתוֹ פְּלִשְׁתִּים׃
וְכָל־הַבְּאֵרֹת אֲשֶׁר חָפְרוּ עַבְדֵי אָבִיו בִּימֵי אַבְרָהָם אָבִיו סִתְּמוּם פְּלִשְׁתִּים וַיְמַלְאוּם עָפָר׃
וַיֹּאמֶר אֲבִימֶלֶךְ אֶל־יִצְחָק לֵךְ מֵעִמָּנוּ כִּי־עָצַמְתָּ־מִמֶּנּוּ מְאֹד׃
וַיֵּלֶךְ מִשָּׁם יִצְחָק וַיִּחַן בְּנַחַל־גְּרָר וַיֵּשֶׁב שָׁם׃
וַיָּשָׁב יִצְחָק וַיַּחְפֹּר אֶת־בְּאֵרֹת הַמַּיִם אֲשֶׁר חָפְרוּ בִּימֵי אַבְרָהָם אָבִיו וַיְסַתְּמוּם פְּלִשְׁתִּים אַחֲרֵי מוֹת אַבְרָהָם וַיִּקְרָא לָהֶן שֵׁמוֹת כַּשֵּׁמֹת אֲשֶׁר־קָרָא לָהֶן אָבִיו׃
וַיַּחְפְּרוּ עַבְדֵי־יִצְחָק בַּנָּחַל וַיִּמְצְאוּ־שָׁם בְּאֵר מַיִם חַיִּים׃
וַיָּרִיבוּ רֹעֵי גְרָר עִם־רֹעֵי יִצְחָק לֵאמֹר לָנוּ הַמָּיִם וַיִּקְרָא שֵׁם־הַבְּאֵר עֵשֶׂק כִּי הִתְעַשְּׂקוּ עִמּוֹ׃
וַיַּחְפְּרוּ בְּאֵר אַחֶרֶת וַיָּרִיבוּ גַּם־עָלֶיהָ וַיִּקְרָא שְׁמָהּ שִׂטְנָה׃
וַיַּעְתֵּק מִשָּׁם וַיַּחְפֹּר בְּאֵר אַחֶרֶת וְלֹא רָבוּ עָלֶיהָ וַיִּקְרָא שְׁמָהּ רְחֹבוֹת וַיֹּאמֶר כִּי־עַתָּה הִרְחִיב יְהוָה לָנוּ וּפָרִינוּ בָאָרֶץ׃
וַיַּעַל מִשָּׁם בְּאֵר שָׁבַע׃
וַיֵּרָא אֵלָיו יְהוָה בַּלַּיְלָה הַהוּא וַיֹּאמֶר אָנֹכִי אֱלֹהֵי אַבְרָהָם אָבִיךָ אַל־תִּירָא כִּי־אִתְּךָ אָנֹכִי וּבֵרַכְתִּיךָ וְהִרְבֵּיתִי אֶת־זַרְעֲךָ בַּעֲבוּר אַבְרָהָם עַבְדִּי׃
וַיִּבֶן שָׁם מִזְבֵּחַ וַיִּקְרָא בְּשֵׁם יְהוָה וַיֶּט־שָׁם אָהֳלוֹ וַיִּכְרוּ־שָׁם עַבְדֵי־יִצְחָק בְּאֵר׃
וַאֲבִימֶלֶךְ הָלַךְ אֵלָיו מִגְּרָר וַאֲחֻזַּת מֵרֵעֵהוּ וּפִיכֹל שַׂר־צְבָאוֹ׃
וַיֹּאמֶר אֲלֵהֶם יִצְחָק מַדּוּעַ בָּאתֶם אֵלָי וְאַתֶּם שְׂנֵאתֶם אֹתִי וַתְּשַׁלְּחוּנִי מֵאִתְּכֶם׃
וַיֹּאמְרוּ רָאוֹ רָאִינוּ כִּי־הָיָה יְהוָה עִמָּךְ וַנֹּאמֶר תְּהִי נָא אָלָה בֵּינוֹתֵינוּ בֵּינֵינוּ וּבֵינֶךָ וְנִכְרְתָה בְרִית עִמָּךְ׃
אִם־תַּעֲשֵׂה עִמָּנוּ רָעָה כַּאֲשֶׁר לֹא נְגַעֲנוּךָ וְכַאֲשֶׁר עָשִׂינוּ עִמְּךָ רַק־טוֹב וַנְּשַׁלֵּחֲךָ בְּשָׁלוֹם אַתָּה עַתָּה בְּרוּךְ יְהוָה׃
וַיַּעַשׂ לָהֶם מִשְׁתֶּה וַיֹּאכְלוּ וַיִּשְׁתּוּ׃
וַיַּשְׁכִּימוּ בַבֹּקֶר וַיִּשָּׁבְעוּ אִישׁ לְאָחִיו וַיְשַׁלְּחֵם יִצְחָק וַיֵּלְכוּ מֵאִתּוֹ בְּשָׁלוֹם׃
וַיְהִי בַּיּוֹם הַהוּא וַיָּבֹאוּ עַבְדֵי יִצְחָק וַיַּגִּדוּ לוֹ עַל־אֹדוֹת הַבְּאֵר אֲשֶׁר חָפָרוּ וַיֹּאמְרוּ לוֹ מָצָאנוּ מָיִם׃
וַיִּקְרָא אֹתָהּ שִׁבְעָה עַל־כֵּן שֵׁם־הָעִיר בְּאֵר שֶׁבַע עַד הַיּוֹם הַזֶּה׃
וַיְהִי עֵשָׂו בֶּן־אַרְבָּעִים שָׁנָה וַיִּקַּח אִשָּׁה אֶת־יְהוּדִית בַּת־בְּאֵרִי הַחִתִּי וְאֶת־בָּשְׂמַת בַּת־אֵילֹן הַחִתִּי׃
וַתִּהְיֶיןָ מֹרַת רוּחַ לְיִצְחָק וּלְרִבְקָה׃

Chapter 27

וַיְהִי כִּי־זָקֵן יִצְחָק וַתִּכְהֶיןָ עֵינָיו מֵרְאֹת וַיִּקְרָא אֶת־עֵשָׂו בְּנוֹ הַגָּדֹל וַיֹּאמֶר אֵלָיו בְּנִי וַיֹּאמֶר אֵלָיו הִנֵּנִי׃
וַיֹּאמֶר הִנֵּה־נָא זָקַנְתִּי לֹא יָדַעְתִּי יוֹם מוֹתִי׃
וְעַתָּה שָׂא־נָא כֵלֶיךָ תֶּלְיְךָ וְקַשְׁתֶּךָ וְצֵא הַשָּׂדֶה וְצוּדָה לִּי צידה [צָיִד׃]
וַעֲשֵׂה־לִי מַטְעַמִּים כַּאֲשֶׁר אָהַבְתִּי וְהָבִיאָה לִּי וְאֹכֵלָה בַּעֲבוּר תְּבָרֶכְךָ נַפְשִׁי בְּטֶרֶם אָמוּת׃
וְרִבְקָה שֹׁמַעַת בְּדַבֵּר יִצְחָק אֶל־עֵשָׂו בְּנוֹ וַיֵּלֶךְ עֵשָׂו הַשָּׂדֶה לָצוּד צַיִד לְהָבִיא׃
וְרִבְקָה אָמְרָה אֶל־יַעֲקֹב בְּנָהּ לֵאמֹר הִנֵּה שָׁמַעְתִּי אֶת־אָבִיךָ מְדַבֵּר אֶל־עֵשָׂו אָחִיךָ לֵאמֹר׃
הָבִיאָה לִּי צַיִד וַעֲשֵׂה־לִי מַטְעַמִּים וְאֹכֵלָה וַאֲבָרֶכְכָה לִפְנֵי יְהוָה לִפְנֵי מוֹתִי׃
וְעַתָּה בְנִי שְׁמַע בְּקֹלִי לַאֲשֶׁר אֲנִי מְצַוָּה אֹתָךְ׃
לֶךְ־נָא אֶל־הַצֹּאן וְקַח־לִי מִשָּׁם שְׁנֵי גְּדָיֵי עִזִּים טֹבִים וְאֶעֱשֶׂה אֹתָם מַטְעַמִּים לְאָבִיךָ כַּאֲשֶׁר אָהֵב׃
וְהֵבֵאתָ לְאָבִיךָ וְאָכָל בַּעֲבֻר אֲשֶׁר יְבָרֶכְךָ לִפְנֵי מוֹתוֹ׃
וַיֹּאמֶר יַעֲקֹב אֶל־רִבְקָה אִמּוֹ הֵן עֵשָׂו אָחִי אִישׁ שָׂעִר וְאָנֹכִי אִישׁ חָלָק׃
אוּלַי יְמֻשֵּׁנִי אָבִי וְהָיִיתִי בְעֵינָיו כִּמְתַעְתֵּעַ וְהֵבֵאתִי עָלַי קְלָלָה וְלֹא בְרָכָה׃
וַתֹּאמֶר לוֹ אִמּוֹ עָלַי קִלְלָתְךָ בְּנִי אַךְ שְׁמַע בְּקֹלִי וְלֵךְ קַח־לִי׃
וַיֵּלֶךְ וַיִּקַּח וַיָּבֵא לְאִמּוֹ וַתַּעַשׂ אִמּוֹ מַטְעַמִּים כַּאֲשֶׁר אָהֵב אָבִיו׃
וַתִּקַּח רִבְקָה אֶת־בִּגְדֵי עֵשָׂו בְּנָהּ הַגָּדֹל הַחֲמֻדֹת אֲשֶׁר אִתָּהּ בַּבָּיִת וַתַּלְבֵּשׁ אֶת־יַעֲקֹב בְּנָהּ הַקָּטָן׃
וְאֵת עֹרֹת גְּדָיֵי הָעִזִּים הִלְבִּישָׁה עַל־יָדָיו וְעַל חֶלְקַת צַוָּארָיו׃
וַתִּתֵּן אֶת־הַמַּטְעַמִּים וְאֶת־הַלֶּחֶם אֲשֶׁר עָשָׂתָה בְּיַד יַעֲקֹב בְּנָהּ׃
וַיָּבֹא אֶל־אָבִיו וַיֹּאמֶר אָבִי וַיֹּאמֶר הִנֶּנִּי מִי אַתָּה בְּנִי׃
וַיֹּאמֶר יַעֲקֹב אֶל־אָבִיו אָנֹכִי עֵשָׂו בְּכֹרֶךָ עָשִׂיתִי כַּאֲשֶׁר דִּבַּרְתָּ אֵלָי קוּם־נָא שְׁבָה וְאָכְלָה מִצֵּידִי בַּעֲבוּר תְּבָרֲכַנִּי נַפְשֶׁךָ׃
וַיֹּאמֶר יִצְחָק אֶל־בְּנוֹ מַה־זֶּה מִהַרְתָּ לִמְצֹא בְּנִי וַיֹּאמֶר כִּי הִקְרָה יְהוָה אֱלֹהֶיךָ לְפָנָי׃
וַיֹּאמֶר יִצְחָק אֶל־יַעֲקֹב גְּשָׁה־נָּא וַאֲמֻשְׁךָ בְּנִי הַאַתָּה זֶה בְּנִי עֵשָׂו אִם־לֹא׃
וַיִּגַּשׁ יַעֲקֹב אֶל־יִצְחָק אָבִיו וַיְמֻשֵּׁהוּ וַיֹּאמֶר הַקֹּל קוֹל יַעֲקֹב וְהַיָּדַיִם יְדֵי עֵשָׂו׃
וְלֹא הִכִּירוֹ כִּי־הָיוּ יָדָיו כִּידֵי עֵשָׂו אָחִיו שְׂעִרֹת וַיְבָרְכֵהוּ׃
וַיֹּאמֶר אַתָּה זֶה בְּנִי עֵשָׂו וַיֹּאמֶר אָנִי׃
וַיֹּאמֶר הַגִּשָׁה לִּי וְאֹכְלָה מִצֵּיד בְּנִי לְמַעַן תְּבָרֶכְךָ נַפְשִׁי וַיַּגֶּשׁ־לוֹ וַיֹּאכַל וַיָּבֵא לוֹ יַיִן וַיֵּשְׁתְּ׃
וַיֹּאמֶר אֵלָיו יִצְחָק אָבִיו גְּשָׁה־נָּא וּשְׁקָה־לִּי בְּנִי׃
וַיִּגַּשׁ וַיִּשַּׁק־לוֹ וַיָּרַח אֶת־רֵיחַ בְּגָדָיו וַיְבָרֲכֵהוּ וַיֹּאמֶר רְאֵה רֵיחַ בְּנִי כְּרֵיחַ שָׂדֶה אֲשֶׁר בֵּרֲכוֹ יְהוָה׃
וְיִתֶּן־לְךָ הָאֱלֹהִים מִטַּל הַשָּׁמַיִם וּמִשְׁמַנֵּי הָאָרֶץ וְרֹב דָּגָן וְתִירֹשׁ׃
יַעַבְדוּךָ עַמִּים וישתחו [וְיִשְׁתַּחֲווּ] לְךָ לְאֻמִּים הֱוֵה גְבִיר לְאַחֶיךָ וְיִשְׁתַּחֲוּוּ לְךָ בְּנֵי אִמֶּךָ אֹרְרֶיךָ אָרוּר וּמְבָרֲכֶיךָ בָּרוּךְ׃
וַיְהִי כַּאֲשֶׁר כִּלָּה יִצְחָק לְבָרֵךְ אֶת־יַעֲקֹב וַיְהִי אַךְ יָצֹא יָצָא יַעֲקֹב מֵאֵת פְּנֵי יִצְחָק אָבִיו וְעֵשָׂו אָחִיו בָּא מִצֵּידוֹ׃
וַיַּעַשׂ גַּם־הוּא מַטְעַמִּים וַיָּבֵא לְאָבִיו וַיֹּאמֶר לְאָבִיו יָקֻם אָבִי וְיֹאכַל מִצֵּיד בְּנוֹ בַּעֲבוּר תְּבָרֲכַנִּי נַפְשֶׁךָ׃
וַיֹּאמֶר לוֹ יִצְחָק אָבִיו מִי־אָתָּה וַיֹּאמֶר אֲנִי בִּנְךָ בְכֹרְךָ עֵשָׂו׃
וַיֶּחֱרַד יִצְחָק חֲרָדָה גְּדֹלָה עַד־מְאֹד וַיֹּאמֶר מִי־אֵפוֹא הוּא הַצָּד־צַיִד וַיָּבֵא לִי וָאֹכַל מִכֹּל בְּטֶרֶם תָּבוֹא וָאֲבָרֲכֵהוּ גַּם־בָּרוּךְ יִהְיֶה׃
כִּשְׁמֹעַ עֵשָׂו אֶת־דִּבְרֵי אָבִיו וַיִּצְעַק צְעָקָה גְּדֹלָה וּמָרָה עַד־מְאֹד וַיֹּאמֶר לְאָבִיו בָּרֲכֵנִי גַם־אָנִי אָבִי׃
וַיֹּאמֶר בָּא אָחִיךָ בְּמִרְמָה וַיִּקַּח בִּרְכָתֶךָ׃
וַיֹּאמֶר הֲכִי קָרָא שְׁמוֹ יַעֲקֹב וַיַּעְקְבֵנִי זֶה פַעֲמַיִם אֶת־בְּכֹרָתִי לָקָח וְהִנֵּה עַתָּה לָקַח בִּרְכָתִי וַיֹּאמַר הֲלֹא־אָצַלְתָּ לִּי בְּרָכָה׃
וַיַּעַן יִצְחָק וַיֹּאמֶר לְעֵשָׂו הֵן גְּבִיר שַׂמְתִּיו לָךְ וְאֶת־כָּל־אֶחָיו נָתַתִּי לוֹ לַעֲבָדִים וְדָגָן וְתִירֹשׁ סְמַכְתִּיו וּלְכָה אֵפוֹא מָה אֶעֱשֶׂה בְּנִי׃
וַיֹּאמֶר עֵשָׂו אֶל־אָבִיו הַבְרָכָה אַחַת הִוא־לְךָ אָבִי בָּרֲכֵנִי גַם־אָנִי אָבִי וַיִּשָּׂא עֵשָׂו קֹלוֹ וַיֵּבְךְּ׃
וַיַּעַן יִצְחָק אָבִיו וַיֹּאמֶר אֵלָיו הִנֵּה מִשְׁמַנֵּי הָאָרֶץ יִהְיֶה מוֹשָׁבֶךָ וּמִטַּל הַשָּׁמַיִם מֵעָל׃
וְעַל־חַרְבְּךָ תִחְיֶה וְאֶת־אָחִיךָ תַּעֲבֹד וְהָיָה כַּאֲשֶׁר תָּרִיד וּפָרַקְתָּ עֻלּוֹ מֵעַל צַוָּארֶךָ׃
וַיִּשְׂטֹם עֵשָׂו אֶת־יַעֲקֹב עַל־הַבְּרָכָה אֲשֶׁר בֵּרֲכוֹ אָבִיו וַיֹּאמֶר עֵשָׂו בְּלִבּוֹ יִקְרְבוּ יְמֵי אֵבֶל אָבִי וְאַהַרְגָה אֶת־יַעֲקֹב אָחִי׃
וַיֻּגַּד לְרִבְקָה אֶת־דִּבְרֵי עֵשָׂו בְּנָהּ הַגָּדֹל וַתִּשְׁלַח וַתִּקְרָא לְיַעֲקֹב בְּנָהּ הַקָּטָן וַתֹּאמֶר אֵלָיו הִנֵּה עֵשָׂו אָחִיךָ מִתְנַחֵם לְךָ לְהָרְגֶךָ׃
וְעַתָּה בְנִי שְׁמַע בְּקֹלִי וְקוּם בְּרַח־לְךָ אֶל־לָבָן אָחִי חָרָנָה׃
וְיָשַׁבְתָּ עִמּוֹ יָמִים אֲחָדִים עַד אֲשֶׁר־תָּשׁוּב חֲמַת אָחִיךָ׃
עַד־שׁוּב אַף־אָחִיךָ מִמְּךָ וְשָׁכַח אֵת אֲשֶׁר־עָשִׂיתָ לּוֹ וְשָׁלַחְתִּי וּלְקַחְתִּיךָ מִשָּׁם לָמָה אֶשְׁכַּל גַּם־שְׁנֵיכֶם יוֹם אֶחָד׃
וַתֹּאמֶר רִבְקָה אֶל־יִצְחָק קַצְתִּי בְחַיַּי מִפְּנֵי בְּנוֹת חֵת אִם־לֹקֵחַ יַעֲקֹב אִשָּׁה מִבְּנוֹת־חֵת כָּאֵלֶּה מִבְּנוֹת הָאָרֶץ לָמָּה לִּי חַיִּים׃

Chapter 28

וַיִּקְרָא יִצְחָק אֶל־יַעֲקֹב וַיְבָרֶךְ אֹתוֹ וַיְצַוֵּהוּ וַיֹּאמֶר לוֹ לֹא־תִקַּח אִשָּׁה מִבְּנוֹת כְּנָעַן׃
קוּם לֵךְ פַּדֶּנָה אֲרָם בֵּיתָה בְתוּאֵל אֲבִי אִמֶּךָ וְקַח־לְךָ מִשָּׁם אִשָּׁה מִבְּנוֹת לָבָן אֲחִי אִמֶּךָ׃
וְאֵל שַׁדַּי יְבָרֵךְ אֹתְךָ וְיַפְרְךָ וְיַרְבֶּךָ וְהָיִיתָ לִקְהַל עַמִּים׃
וְיִתֶּן־לְךָ אֶת־בִּרְכַּת אַבְרָהָם לְךָ וּלְזַרְעֲךָ אִתָּךְ לְרִשְׁתְּךָ אֶת־אֶרֶץ מְגֻרֶיךָ אֲשֶׁר־נָתַן אֱלֹהִים לְאַבְרָהָם׃
וַיִּשְׁלַח יִצְחָק אֶת־יַעֲקֹב וַיֵּלֶךְ פַּדֶּנָה אֲרָם אֶל־לָבָן בֶּן־בְּתוּאֵל הָאֲרַמִּי אֲחִי רִבְקָה אֵם יַעֲקֹב וְעֵשָׂו׃
וַיַּרְא עֵשָׂו כִּי־בֵרַךְ יִצְחָק אֶת־יַעֲקֹב וְשִׁלַּח אֹתוֹ פַּדֶּנָה אֲרָם לָקַחַת־לוֹ מִשָּׁם אִשָּׁה בְּבָרֲכוֹ אֹתוֹ וַיְצַו עָלָיו לֵאמֹר לֹא־תִקַּח אִשָּׁה מִבְּנוֹת כְּנָעַן׃
וַיִּשְׁמַע יַעֲקֹב אֶל־אָבִיו וְאֶל־אִמּוֹ וַיֵּלֶךְ פַּדֶּנָה אֲרָם׃
וַיַּרְא עֵשָׂו כִּי רָעוֹת בְּנוֹת כְּנָעַן בְּעֵינֵי יִצְחָק אָבִיו׃
וַיֵּלֶךְ עֵשָׂו אֶל־יִשְׁמָעֵאל וַיִּקַּח אֶת־מָחֲלַת בַּת־יִשְׁמָעֵאל בֶּן־אַבְרָהָם אֲחוֹת נְבָיוֹת עַל־נָשָׁיו לוֹ לְאִשָּׁה׃
וַיֵּצֵא יַעֲקֹב מִבְּאֵר שָׁבַע וַיֵּלֶךְ חָרָנָה׃
וַיִּפְגַּע בַּמָּקוֹם וַיָּלֶן שָׁם כִּי־בָא הַשֶּׁמֶשׁ וַיִּקַּח מֵאַבְנֵי הַמָּקוֹם וַיָּשֶׂם מְרַאֲשֹׁתָיו וַיִּשְׁכַּב בַּמָּקוֹם הַהוּא׃
וַיַּחֲלֹם וְהִנֵּה סֻלָּם מֻצָּב אַרְצָה וְרֹאשׁוֹ מַגִּיעַ הַשָּׁמָיְמָה וְהִנֵּה מַלְאֲכֵי אֱלֹהִים עֹלִים וְיֹרְדִים בּוֹ׃
וְהִנֵּה יְהוָה נִצָּב עָלָיו וַיֹּאמַר אֲנִי יְהוָה אֱלֹהֵי אַבְרָהָם אָבִיךָ וֵאלֹהֵי יִצְחָק הָאָרֶץ אֲשֶׁר אַתָּה שֹׁכֵב עָלֶיהָ לְךָ אֶתְּנֶנָּה וּלְזַרְעֶךָ׃
וְהָיָה זַרְעֲךָ כַּעֲפַר הָאָרֶץ וּפָרַצְתָּ יָמָּה וָקֵדְמָה וְצָפֹנָה וָנֶגְבָּה וְנִבְרֲכוּ בְךָ כָּל־מִשְׁפְּחֹת הָאֲדָמָה וּבְזַרְעֶךָ׃
וְהִנֵּה אָנֹכִי עִמָּךְ וּשְׁמַרְתִּיךָ בְּכֹל אֲשֶׁר־תֵּלֵךְ וַהֲשִׁבֹתִיךָ אֶל־הָאֲדָמָה הַזֹּאת כִּי לֹא אֶעֱזָבְךָ עַד אֲשֶׁר אִם־עָשִׂיתִי אֵת אֲשֶׁר־דִּבַּרְתִּי לָךְ׃
וַיִּיקַץ יַעֲקֹב מִשְּׁנָתוֹ וַיֹּאמֶר אָכֵן יֵשׁ יְהוָה בַּמָּקוֹם הַזֶּה וְאָנֹכִי לֹא יָדָעְתִּי׃
וַיִּירָא וַיֹּאמַר מַה־נּוֹרָא הַמָּקוֹם הַזֶּה אֵין זֶה כִּי אִם־בֵּית אֱלֹהִים וְזֶה שַׁעַר הַשָּׁמָיִם׃
וַיַּשְׁכֵּם יַעֲקֹב בַּבֹּקֶר וַיִּקַּח אֶת־הָאֶבֶן אֲשֶׁר־שָׂם מְרַאֲשֹׁתָיו וַיָּשֶׂם אֹתָהּ מַצֵּבָה וַיִּצֹק שֶׁמֶן עַל־רֹאשָׁהּ׃
וַיִּקְרָא אֶת־שֵׁם־הַמָּקוֹם הַהוּא בֵּית־אֵל וְאוּלָם לוּז שֵׁם־הָעִיר לָרִאשֹׁנָה׃
וַיִּדַּר יַעֲקֹב נֶדֶר לֵאמֹר אִם־יִהְיֶה אֱלֹהִים עִמָּדִי וּשְׁמָרַנִי בַּדֶּרֶךְ הַזֶּה אֲשֶׁר אָנֹכִי הוֹלֵךְ וְנָתַן־לִי לֶחֶם לֶאֱכֹל וּבֶגֶד לִלְבֹּשׁ׃
וְשַׁבְתִּי בְשָׁלוֹם אֶל־בֵּית אָבִי וְהָיָה יְהוָה לִי לֵאלֹהִים׃
וְהָאֶבֶן הַזֹּאת אֲשֶׁר־שַׂמְתִּי מַצֵּבָה יִהְיֶה בֵּית אֱלֹהִים וְכֹל אֲשֶׁר תִּתֶּן־לִי עַשֵּׂר אֲעַשְּׂרֶנּוּ לָךְ׃

Chapter 29

וַיִּשָּׂא יַעֲקֹב רַגְלָיו וַיֵּלֶךְ אַרְצָה בְנֵי־קֶדֶם׃
וַיַּרְא וְהִנֵּה בְאֵר בַּשָּׂדֶה וְהִנֵּה־שָׁם שְׁלֹשָׁה עֶדְרֵי־צֹאן רֹבְצִים עָלֶיהָ כִּי מִן־הַבְּאֵר הַהִוא יַשְׁקוּ הָעֲדָרִים וְהָאֶבֶן גְּדֹלָה עַל־פִּי הַבְּאֵר׃
וְנֶאֶסְפוּ־שָׁמָּה כָל־הָעֲדָרִים וְגָלֲלוּ אֶת־הָאֶבֶן מֵעַל פִּי הַבְּאֵר וְהִשְׁקוּ אֶת־הַצֹּאן וְהֵשִׁיבוּ אֶת־הָאֶבֶן עַל־פִּי הַבְּאֵר לִמְקֹמָהּ׃
וַיֹּאמֶר לָהֶם יַעֲקֹב אַחַי מֵאַיִן אַתֶּם וַיֹּאמְרוּ מֵחָרָן אֲנָחְנוּ׃
וַיֹּאמֶר לָהֶם הַיְדַעְתֶּם אֶת־לָבָן בֶּן־נָחוֹר וַיֹּאמְרוּ יָדָעְנוּ׃
וַיֹּאמֶר לָהֶם הֲשָׁלוֹם לוֹ וַיֹּאמְרוּ שָׁלוֹם וְהִנֵּה רָחֵל בִּתּוֹ בָּאָה עִם־הַצֹּאן׃
וַיֹּאמֶר הֵן עוֹד הַיּוֹם גָּדוֹל לֹא־עֵת הֵאָסֵף הַמִּקְנֶה הַשְׁקוּ הַצֹּאן וּלְכוּ רְעוּ׃
וַיֹּאמְרוּ לֹא נוּכַל עַד אֲשֶׁר יֵאָסְפוּ כָּל־הָעֲדָרִים וְגָלֲלוּ אֶת־הָאֶבֶן מֵעַל פִּי הַבְּאֵר וְהִשְׁקִינוּ הַצֹּאן׃
עוֹדֶנּוּ מְדַבֵּר עִמָּם וְרָחֵל בָּאָה עִם־הַצֹּאן אֲשֶׁר לְאָבִיהָ כִּי רֹעָה הִוא׃
וַיְהִי כַּאֲשֶׁר רָאָה יַעֲקֹב אֶת־רָחֵל בַּת־לָבָן אֲחִי אִמּוֹ וְאֶת־צֹאן לָבָן אֲחִי אִמּוֹ וַיִּגַּשׁ יַעֲקֹב וַיָּגֶל אֶת־הָאֶבֶן מֵעַל פִּי הַבְּאֵר וַיַּשְׁקְ אֶת־צֹאן לָבָן אֲחִי אִמּוֹ׃
וַיִּשַּׁק יַעֲקֹב לְרָחֵל וַיִּשָּׂא אֶת־קֹלוֹ וַיֵּבְךְּ׃
וַיַּגֵּד יַעֲקֹב לְרָחֵל כִּי אֲחִי אָבִיהָ הוּא וְכִי בֶן־רִבְקָה הוּא וַתָּרָץ וַתַּגֵּד לְאָבִיהָ׃
וַיְהִי כִשְׁמֹעַ לָבָן אֶת־שֵׁמַע יַעֲקֹב בֶּן־אֲחֹתוֹ וַיָּרָץ לִקְרָאתוֹ וַיְחַבֶּק־לוֹ וַיְנַשֶּׁק־לוֹ וַיְבִיאֵהוּ אֶל־בֵּיתוֹ וַיְסַפֵּר לְלָבָן אֵת כָּל־הַדְּבָרִים הָאֵלֶּה׃
וַיֹּאמֶר לוֹ לָבָן אַךְ עַצְמִי וּבְשָׂרִי אָתָּה וַיֵּשֶׁב עִמּוֹ חֹדֶשׁ יָמִים׃
וַיֹּאמֶר לָבָן לְיַעֲקֹב הֲכִי־אָחִי אַתָּה וַעֲבַדְתַּנִי חִנָּם הַגִּידָה לִּי מַה־מַּשְׂכֻּרְתֶּךָ׃
וּלְלָבָן שְׁתֵּי בָנוֹת שֵׁם הַגְּדֹלָה לֵאָה וְשֵׁם הַקְּטַנָּה רָחֵל׃
וְעֵינֵי לֵאָה רַכּוֹת וְרָחֵל הָיְתָה יְפַת־תֹּאַר וִיפַת מַרְאֶה׃
וַיֶּאֱהַב יַעֲקֹב אֶת־רָחֵל וַיֹּאמֶר אֶעֱבָדְךָ שֶׁבַע שָׁנִים בְּרָחֵל בִּתְּךָ הַקְּטַנָּה׃
וַיֹּאמֶר לָבָן טוֹב תִּתִּי אֹתָהּ לָךְ מִתִּתִּי אֹתָהּ לְאִישׁ אַחֵר שְׁבָה עִמָּדִי׃
וַיַּעֲבֹד יַעֲקֹב בְּרָחֵל שֶׁבַע שָׁנִים וַיִּהְיוּ בְעֵינָיו כְּיָמִים אֲחָדִים בְּאַהֲבָתוֹ אֹתָהּ׃
וַיֹּאמֶר יַעֲקֹב אֶל־לָבָן הָבָה אֶת־אִשְׁתִּי כִּי מָלְאוּ יָמָי וְאָבוֹאָה אֵלֶיהָ׃
וַיֶּאֱסֹף לָבָן אֶת־כָּל־אַנְשֵׁי הַמָּקוֹם וַיַּעַשׂ מִשְׁתֶּה׃
וַיְהִי בָעֶרֶב וַיִּקַּח אֶת־לֵאָה בִתּוֹ וַיָּבֵא אֹתָהּ אֵלָיו וַיָּבֹא אֵלֶיהָ׃
וַיִּתֵּן לָבָן לָהּ אֶת־זִלְפָּה שִׁפְחָתוֹ לְלֵאָה בִתּוֹ שִׁפְחָה׃
וַיְהִי בַבֹּקֶר וְהִנֵּה־הִוא לֵאָה וַיֹּאמֶר אֶל־לָבָן מַה־זֹּאת עָשִׂיתָ לִּי הֲלֹא בְרָחֵל עָבַדְתִּי עִמָּךְ וְלָמָּה רִמִּיתָנִי׃
וַיֹּאמֶר לָבָן לֹא־יֵעָשֶׂה כֵן בִּמְקוֹמֵנוּ לָתֵת הַצְּעִירָה לִפְנֵי הַבְּכִירָה׃
מַלֵּא שְׁבֻעַ זֹאת וְנִתְּנָה לְךָ גַּם־אֶת־זֹאת בַּעֲבֹדָה אֲשֶׁר תַּעֲבֹד עִמָּדִי עוֹד שֶׁבַע־שָׁנִים אֲחֵרוֹת׃
וַיַּעַשׂ יַעֲקֹב כֵּן וַיְמַלֵּא שְׁבֻעַ זֹאת וַיִּתֶּן־לוֹ אֶת־רָחֵל בִּתּוֹ לוֹ לְאִשָּׁה׃
וַיִּתֵּן לָבָן לְרָחֵל בִּתּוֹ אֶת־בִּלְהָה שִׁפְחָתוֹ לָהּ לְשִׁפְחָה׃
וַיָּבֹא גַּם אֶל־רָחֵל וַיֶּאֱהַב גַּם־אֶת־רָחֵל מִלֵּאָה וַיַּעֲבֹד עִמּוֹ עוֹד שֶׁבַע־שָׁנִים אֲחֵרוֹת׃
וַיַּרְא יְהוָה כִּי־שְׂנוּאָה לֵאָה וַיִּפְתַּח אֶת־רַחְמָהּ וְרָחֵל עֲקָרָה׃
וַתַּהַר לֵאָה וַתֵּלֶד בֵּן וַתִּקְרָא שְׁמוֹ רְאוּבֵן כִּי אָמְרָה כִּי־רָאָה יְהוָה בְּעָנְיִי כִּי עַתָּה יֶאֱהָבַנִי אִישִׁי׃
וַתַּהַר עוֹד וַתֵּלֶד בֵּן וַתֹּאמֶר כִּי־שָׁמַע יְהוָה כִּי־שְׂנוּאָה אָנֹכִי וַיִּתֶּן־לִי גַּם־אֶת־זֶה וַתִּקְרָא שְׁמוֹ שִׁמְעוֹן׃
וַתַּהַר עוֹד וַתֵּלֶד בֵּן וַתֹּאמֶר עַתָּה הַפַּעַם יִלָּוֶה אִישִׁי אֵלַי כִּי־יָלַדְתִּי לוֹ שְׁלֹשָׁה בָנִים עַל־כֵּן קָרָא־שְׁמוֹ לֵוִי׃
וַתַּהַר עוֹד וַתֵּלֶד בֵּן וַתֹּאמֶר הַפַּעַם אוֹדֶה אֶת־יְהוָה עַל־כֵּן קָרְאָה שְׁמוֹ יְהוּדָה וַתַּעֲמֹד מִלֶּדֶת׃

Chapter 30

וַתֵּרֶא רָחֵל כִּי לֹא יָלְדָה לְיַעֲקֹב וַתְּקַנֵּא רָחֵל בַּאֲחֹתָהּ וַתֹּאמֶר אֶל־יַעֲקֹב הָבָה־לִּי בָנִים וְאִם־אַיִן מֵתָה אָנֹכִי׃
וַיִּחַר־אַף יַעֲקֹב בְּרָחֵל וַיֹּאמֶר הֲתַחַת אֱלֹהִים אָנֹכִי אֲשֶׁר־מָנַע מִמֵּךְ פְּרִי־בָטֶן׃
וַתֹּאמֶר הִנֵּה אֲמָתִי בִלְהָה בֹּא אֵלֶיהָ וְתֵלֵד עַל־בִּרְכַּי וְאִבָּנֶה גַם־אָנֹכִי מִמֶּנָּה׃
וַתִּתֶּן־לוֹ אֶת־בִּלְהָה שִׁפְחָתָהּ לְאִשָּׁה וַיָּבֹא אֵלֶיהָ יַעֲקֹב׃
וַתַּהַר בִּלְהָה וַתֵּלֶד לְיַעֲקֹב בֵּן׃
וַתֹּאמֶר רָחֵל דָּנַנִּי אֱלֹהִים וְגַם שָׁמַע בְּקֹלִי וַיִּתֶּן־לִי בֵּן עַל־כֵּן קָרְאָה שְׁמוֹ דָּן׃
וַתַּהַר עוֹד וַתֵּלֶד בִּלְהָה שִׁפְחַת רָחֵל בֵּן שֵׁנִי לְיַעֲקֹב׃
וַתֹּאמֶר רָחֵל נַפְתּוּלֵי אֱלֹהִים נִפְתַּלְתִּי עִם־אֲחֹתִי גַּם־יָכֹלְתִּי וַתִּקְרָא שְׁמוֹ נַפְתָּלִי׃
וַתֵּרֶא לֵאָה כִּי עָמְדָה מִלֶּדֶת וַתִּקַּח אֶת־זִלְפָּה שִׁפְחָתָהּ וַתִּתֵּן אֹתָהּ לְיַעֲקֹב לְאִשָּׁה׃
וַתֵּלֶד זִלְפָּה שִׁפְחַת לֵאָה לְיַעֲקֹב בֵּן׃
וַתֹּאמֶר לֵאָה בגד [בָּא] [גָד] וַתִּקְרָא אֶת־שְׁמוֹ גָּד׃
וַתֵּלֶד זִלְפָּה שִׁפְחַת לֵאָה בֵּן שֵׁנִי לְיַעֲקֹב׃
וַתֹּאמֶר לֵאָה בְּאָשְׁרִי כִּי אִשְּׁרוּנִי בָּנוֹת וַתִּקְרָא אֶת־שְׁמוֹ אָשֵׁר׃
וַיֵּלֶךְ רְאוּבֵן בִּימֵי קְצִיר־חִטִּים וַיִּמְצָא דוּדָאִים בַּשָּׂדֶה וַיָּבֵא אֹתָם אֶל־לֵאָה אִמּוֹ וַתֹּאמֶר רָחֵל אֶל־לֵאָה תְּנִי־נָא לִי מִדּוּדָאֵי בְּנֵךְ׃
וַתֹּאמֶר לָהּ הַמְעַט קַחְתֵּךְ אֶת־אִישִׁי וְלָקַחַת גַּם אֶת־דּוּדָאֵי בְּנִי וַתֹּאמֶר רָחֵל לָכֵן יִשְׁכַּב עִמָּךְ הַלַּיְלָה תַּחַת דּוּדָאֵי בְנֵךְ׃
וַיָּבֹא יַעֲקֹב מִן־הַשָּׂדֶה בָּעֶרֶב וַתֵּצֵא לֵאָה לִקְרָאתוֹ וַתֹּאמֶר אֵלַי תָּבוֹא כִּי שָׂכֹר שְׂכַרְתִּיךָ בְּדוּדָאֵי בְּנִי וַיִּשְׁכַּב עִמָּהּ בַּלַּיְלָה הוּא׃
וַיִּשְׁמַע אֱלֹהִים אֶל־לֵאָה וַתַּהַר וַתֵּלֶד לְיַעֲקֹב בֵּן חֲמִישִׁי׃
וַתֹּאמֶר לֵאָה נָתַן אֱלֹהִים שְׂכָרִי אֲשֶׁר־נָתַתִּי שִׁפְחָתִי לְאִישִׁי וַתִּקְרָא שְׁמוֹ יִשָּׂשכָר׃
וַתַּהַר עוֹד לֵאָה וַתֵּלֶד בֵּן־שִׁשִּׁי לְּיַעֲקֹב׃
וַתֹּאמֶר לֵאָה זְבָדַנִי אֱלֹהִים אֹתִי זֵבֶד טוֹב הַפַּעַם יִזְבְּלֵנִי אִישִׁי כִּי־יָלַדְתִּי לוֹ שִׁשָּׁה בָנִים וַתִּקְרָא אֶת־שְׁמוֹ זְבֻלוּן׃
וְאַחַר יָלְדָה בַּת וַתִּקְרָא אֶת־שְׁמָהּ דִּינָה׃
וַיִּזְכֹּר אֱלֹהִים אֶת־רָחֵל וַיִּשְׁמַע אֵלֶיהָ אֱלֹהִים וַיִּפְתַּח אֶת־רַחְמָהּ׃
וַתַּהַר וַתֵּלֶד בֵּן וַתֹּאמֶר אָסַף אֱלֹהִים אֶת־חֶרְפָּתִי׃
וַתִּקְרָא אֶת־שְׁמוֹ יוֹסֵף לֵאמֹר יֹסֵף יְהוָה לִי בֵּן אַחֵר׃
וַיְהִי כַּאֲשֶׁר יָלְדָה רָחֵל אֶת־יוֹסֵף וַיֹּאמֶר יַעֲקֹב אֶל־לָבָן שַׁלְּחֵנִי וְאֵלְכָה אֶל־מְקוֹמִי וּלְאַרְצִי׃
תְּנָה אֶת־נָשַׁי וְאֶת־יְלָדַי אֲשֶׁר עָבַדְתִּי אֹתְךָ בָּהֵן וְאֵלֵכָה כִּי אַתָּה יָדַעְתָּ אֶת־עֲבֹדָתִי אֲשֶׁר עֲבַדְתִּיךָ׃
וַיֹּאמֶר אֵלָיו לָבָן אִם־נָא מָצָאתִי חֵן בְּעֵינֶיךָ נִחַשְׁתִּי וַיְבָרֲכֵנִי יְהוָה בִּגְלָלֶךָ׃
וַיֹּאמַר נָקְבָה שְׂכָרְךָ עָלַי וְאֶתֵּנָה׃
וַיֹּאמֶר אֵלָיו אַתָּה יָדַעְתָּ אֵת אֲשֶׁר עֲבַדְתִּיךָ וְאֵת אֲשֶׁר־הָיָה מִקְנְךָ אִתִּי׃
כִּי מְעַט אֲשֶׁר־הָיָה לְךָ לְפָנַי וַיִּפְרֹץ לָרֹב וַיְבָרֶךְ יְהוָה אֹתְךָ לְרַגְלִי וְעַתָּה מָתַי אֶעֱשֶׂה גַם־אָנֹכִי לְבֵיתִי׃
וַיֹּאמֶר מָה אֶתֶּן־לָךְ וַיֹּאמֶר יַעֲקֹב לֹא־תִתֶּן־לִי מְאוּמָה אִם־תַּעֲשֶׂה־לִּי הַדָּבָר הַזֶּה אָשׁוּבָה אֶרְעֶה צֹאנְךָ אֶשְׁמֹר׃
אֶעֱבֹר בְּכָל־צֹאנְךָ הַיּוֹם הָסֵר מִשָּׁם כָּל־שֶׂה נָקֹד וְטָלוּא וְכָל־שֶׂה־חוּם בַּכְּשָׂבִים וְטָלוּא וְנָקֹד בָּעִזִּים וְהָיָה שְׂכָרִי׃
וְעָנְתָה־בִּי צִדְקָתִי בְּיוֹם מָחָר כִּי־תָבוֹא עַל־שְׂכָרִי לְפָנֶיךָ כֹּל אֲשֶׁר־אֵינֶנּוּ נָקֹד וְטָלוּא בָּעִזִּים וְחוּם בַּכְּשָׂבִים גָּנוּב הוּא אִתִּי׃
וַיֹּאמֶר לָבָן הֵן לוּ יְהִי כִדְבָרֶךָ׃
וַיָּסַר בַּיּוֹם הַהוּא אֶת־הַתְּיָשִׁים הָעֲקֻדִּים וְהַטְּלֻאִים וְאֵת כָּל־הָעִזִּים הַנְּקֻדּוֹת וְהַטְּלֻאֹת כֹּל אֲשֶׁר־לָבָן בּוֹ וְכָל־חוּם בַּכְּשָׂבִים וַיִּתֵּן בְּיַד־בָּנָיו׃
וַיָּשֶׂם דֶּרֶךְ שְׁלֹשֶׁת יָמִים בֵּינוֹ וּבֵין יַעֲקֹב וְיַעֲקֹב רֹעֶה אֶת־צֹאן לָבָן הַנּוֹתָרֹת׃
וַיִּקַּח־לוֹ יַעֲקֹב מַקַּל לִבְנֶה לַח וְלוּז וְעֶרְמוֹן וַיְפַצֵּל בָּהֵן פְּצָלוֹת לְבָנוֹת מַחְשֹׂף הַלָּבָן אֲשֶׁר עַל־הַמַּקְלוֹת׃
וַיַּצֵּג אֶת־הַמַּקְלוֹת אֲשֶׁר פִּצֵּל בָּרֳהָטִים בְּשִׁקֲתוֹת הַמָּיִם אֲשֶׁר תָּבֹאןָ הַצֹּאן לִשְׁתּוֹת לְנֹכַח הַצֹּאן וַיֵּחַמְנָה בְּבֹאָן לִשְׁתּוֹת׃
וַיֶּחֱמוּ הַצֹּאן אֶל־הַמַּקְלוֹת וַתֵּלַדְןָ הַצֹּאן עֲקֻדִּים נְקֻדִּים וּטְלֻאִים׃
וְהַכְּשָׂבִים הִפְרִיד יַעֲקֹב וַיִּתֵּן פְּנֵי הַצֹּאן אֶל־עָקֹד וְכָל־חוּם בְּצֹאן לָבָן וַיָּשֶׁת־לוֹ עֲדָרִים לְבַדּוֹ וְלֹא שָׁתָם עַל־צֹאן לָבָן׃
וְהָיָה בְּכָל־יַחֵם הַצֹּאן הַמְקֻשָּׁרוֹת וְשָׂם יַעֲקֹב אֶת־הַמַּקְלוֹת לְעֵינֵי הַצֹּאן בָּרֳהָטִים לְיַחְמֵנָּה בַּמַּקְלוֹת׃
וּבְהַעֲטִיף הַצֹּאן לֹא יָשִׂים וְהָיָה הָעֲטֻפִים לְלָבָן וְהַקְּשֻׁרִים לְיַעֲקֹב׃
וַיִּפְרֹץ הָאִישׁ מְאֹד מְאֹד וַיְהִי־לוֹ צֹאן רַבּוֹת וּשְׁפָחוֹת וַעֲבָדִים וּגְמַלִּים וַחֲמֹרִים׃

Chapter 31

וַיִּשְׁמַע אֶת־דִּבְרֵי בְנֵי־לָבָן לֵאמֹר לָקַח יַעֲקֹב אֵת כָּל־אֲשֶׁר לְאָבִינוּ וּמֵאֲשֶׁר לְאָבִינוּ עָשָׂה אֵת כָּל־הַכָּבֹד הַזֶּה׃
וַיַּרְא יַעֲקֹב אֶת־פְּנֵי לָבָן וְהִנֵּה אֵינֶנּוּ עִמּוֹ כִּתְמוֹל שִׁלְשׁוֹם׃
וַיֹּאמֶר יְהוָה אֶל־יַעֲקֹב שׁוּב אֶל־אֶרֶץ אֲבוֹתֶיךָ וּלְמוֹלַדְתֶּךָ וְאֶהְיֶה עִמָּךְ׃
וַיִּשְׁלַח יַעֲקֹב וַיִּקְרָא לְרָחֵל וּלְלֵאָה הַשָּׂדֶה אֶל־צֹאנוֹ׃
וַיֹּאמֶר לָהֶן רֹאֶה אָנֹכִי אֶת־פְּנֵי אֲבִיכֶן כִּי־אֵינֶנּוּ אֵלַי כִּתְמֹל שִׁלְשֹׁם וֵאלֹהֵי אָבִי הָיָה עִמָּדִי׃
וְאַתֵּנָה יְדַעְתֶּן כִּי בְּכָל־כֹּחִי עָבַדְתִּי אֶת־אֲבִיכֶן׃
וַאֲבִיכֶן הֵתֶל בִּי וְהֶחֱלִף אֶת־מַשְׂכֻּרְתִּי עֲשֶׂרֶת מֹנִים וְלֹא־נְתָנוֹ אֱלֹהִים לְהָרַע עִמָּדִי׃
אִם־כֹּה יֹאמַר נְקֻדִּים יִהְיֶה שְׂכָרֶךָ וְיָלְדוּ כָל־הַצֹּאן נְקֻדִּים וְאִם־כֹּה יֹאמַר עֲקֻדִּים יִהְיֶה שְׂכָרֶךָ וְיָלְדוּ כָל־הַצֹּאן עֲקֻדִּים׃
וַיַּצֵּל אֱלֹהִים אֶת־מִקְנֵה אֲבִיכֶם וַיִּתֶּן־לִי׃
וַיְהִי בְּעֵת יַחֵם הַצֹּאן וָאֶשָּׂא עֵינַי וָאֵרֶא בַּחֲלוֹם וְהִנֵּה הָעַתֻּדִים הָעֹלִים עַל־הַצֹּאן עֲקֻדִּים נְקֻדִּים וּבְרֻדִּים׃
וַיֹּאמֶר אֵלַי מַלְאַךְ הָאֱלֹהִים בַּחֲלוֹם יַעֲקֹב וָאֹמַר הִנֵּנִי׃
וַיֹּאמֶר שָׂא־נָא עֵינֶיךָ וּרְאֵה כָּל־הָעַתֻּדִים הָעֹלִים עַל־הַצֹּאן עֲקֻדִּים נְקֻדִּים וּבְרֻדִּים כִּי רָאִיתִי אֵת כָּל־אֲשֶׁר לָבָן עֹשֶׂה לָּךְ׃
אָנֹכִי הָאֵל בֵּית־אֵל אֲשֶׁר מָשַׁחְתָּ שָּׁם מַצֵּבָה אֲשֶׁר נָדַרְתָּ לִּי שָׁם נֶדֶר עַתָּה קוּם צֵא מִן־הָאָרֶץ הַזֹּאת וְשׁוּב אֶל־אֶרֶץ מוֹלַדְתֶּךָ׃
וַתַּעַן רָחֵל וְלֵאָה וַתֹּאמַרְנָה לוֹ הַעוֹד לָנוּ חֵלֶק וְנַחֲלָה בְּבֵית אָבִינוּ׃
הֲלוֹא נָכְרִיּוֹת נֶחְשַׁבְנוּ לוֹ כִּי מְכָרָנוּ וַיֹּאכַל גַּם־אָכוֹל אֶת־כַּסְפֵּנוּ׃
כִּי כָל־הָעֹשֶׁר אֲשֶׁר הִצִּיל אֱלֹהִים מֵאָבִינוּ לָנוּ הוּא וּלְבָנֵינוּ וְעַתָּה כֹּל אֲשֶׁר אָמַר אֱלֹהִים אֵלֶיךָ עֲשֵׂה׃
וַיָּקָם יַעֲקֹב וַיִּשָּׂא אֶת־בָּנָיו וְאֶת־נָשָׁיו עַל־הַגְּמַלִּים׃
וַיִּנְהַג אֶת־כָּל־מִקְנֵהוּ וְאֶת־כָּל־רְכֻשׁוֹ אֲשֶׁר רָכָשׁ מִקְנֵה קִנְיָנוֹ אֲשֶׁר רָכַשׁ בְּפַדַּן אֲרָם לָבוֹא אֶל־יִצְחָק אָבִיו אַרְצָה כְּנָעַן׃
וְלָבָן הָלַךְ לִגְזֹז אֶת־צֹאנוֹ וַתִּגְנֹב רָחֵל אֶת־הַתְּרָפִים אֲשֶׁר לְאָבִיהָ׃
וַיִּגְנֹב יַעֲקֹב אֶת־לֵב לָבָן הָאֲרַמִּי עַל־בְּלִי הִגִּיד לוֹ כִּי בֹרֵחַ הוּא׃
וַיִּבְרַח הוּא וְכָל־אֲשֶׁר־לוֹ וַיָּקָם וַיַּעֲבֹר אֶת־הַנָּהָר וַיָּשֶׂם אֶת־פָּנָיו הַר הַגִּלְעָד׃
וַיֻּגַּד לְלָבָן בַּיּוֹם הַשְּׁלִישִׁי כִּי בָרַח יַעֲקֹב׃
וַיִּקַּח אֶת־אֶחָיו עִמּוֹ וַיִּרְדֹּף אַחֲרָיו דֶּרֶךְ שִׁבְעַת יָמִים וַיַּדְבֵּק אֹתוֹ בְּהַר הַגִּלְעָד׃
וַיָּבֹא אֱלֹהִים אֶל־לָבָן הָאֲרַמִּי בַּחֲלֹם הַלָּיְלָה וַיֹּאמֶר לוֹ הִשָּׁמֶר לְךָ פֶּן־תְּדַבֵּר עִם־יַעֲקֹב מִטּוֹב עַד־רָע׃
וַיַּשֵּׂג לָבָן אֶת־יַעֲקֹב וְיַעֲקֹב תָּקַע אֶת־אָהֳלוֹ בָּהָר וְלָבָן תָּקַע אֶת־אֶחָיו בְּהַר הַגִּלְעָד׃
וַיֹּאמֶר לָבָן לְיַעֲקֹב מֶה עָשִׂיתָ וַתִּגְנֹב אֶת־לְבָבִי וַתְּנַהֵג אֶת־בְּנֹתַי כִּשְׁבֻיוֹת חָרֶב׃
לָמָּה נַחְבֵּאתָ לִבְרֹחַ וַתִּגְנֹב אֹתִי וְלֹא־הִגַּדְתָּ לִּי וָאֲשַׁלֵּחֲךָ בְּשִׂמְחָה וּבְשִׁרִים בְּתֹף וּבְכִנּוֹר׃
וְלֹא נְטַשְׁתַּנִי לְנַשֵּׁק לְבָנַי וְלִבְנֹתָי עַתָּה הִסְכַּלְתָּ עֲשׂוֹ׃
יֶשׁ־לְאֵל יָדִי לַעֲשׂוֹת עִמָּכֶם רָע וֵאלֹהֵי אֲבִיכֶם אֶמֶשׁ אָמַר אֵלַי לֵאמֹר הִשָּׁמֶר לְךָ מִדַּבֵּר עִם־יַעֲקֹב מִטּוֹב עַד־רָע׃
וְעַתָּה הָלֹךְ הָלַכְתָּ כִּי־נִכְסֹף נִכְסַפְתָּה לְבֵית אָבִיךָ לָמָּה גָנַבְתָּ אֶת־אֱלֹהָי׃
וַיַּעַן יַעֲקֹב וַיֹּאמֶר לְלָבָן כִּי יָרֵאתִי כִּי אָמַרְתִּי פֶּן־תִּגְזֹל אֶת־בְּנוֹתֶיךָ מֵעִמִּי׃
עִם אֲשֶׁר תִּמְצָא אֶת־אֱלֹהֶיךָ לֹא יִחְיֶה נֶגֶד אַחֵינוּ הַכֶּר־לְךָ מָה עִמָּדִי וְקַח־לָךְ וְלֹא־יָדַע יַעֲקֹב כִּי רָחֵל גְּנָבָתַם׃
וַיָּבֹא לָבָן בְּאֹהֶל יַעֲקֹב וּבְאֹהֶל לֵאָה וּבְאֹהֶל שְׁתֵּי הָאֲמָהֹת וְלֹא מָצָא וַיֵּצֵא מֵאֹהֶל לֵאָה וַיָּבֹא בְּאֹהֶל רָחֵל׃
וְרָחֵל לָקְחָה אֶת־הַתְּרָפִים וַתְּשִׂמֵם בְּכַר הַגָּמָל וַתֵּשֶׁב עֲלֵיהֶם וַיְמַשֵּׁשׁ לָבָן אֶת־כָּל־הָאֹהֶל וְלֹא מָצָא׃
וַתֹּאמֶר אֶל־אָבִיהָ אַל־יִחַר בְּעֵינֵי אֲדֹנִי כִּי לוֹא אוּכַל לָקוּם מִפָּנֶיךָ כִּי־דֶרֶךְ נָשִׁים לִי וַיְחַפֵּשׂ וְלֹא מָצָא אֶת־הַתְּרָפִים׃
וַיִּחַר לְיַעֲקֹב וַיָּרֶב בְּלָבָן וַיַּעַן יַעֲקֹב וַיֹּאמֶר לְלָבָן מַה־פִּשְׁעִי מַה חַטָּאתִי כִּי דָלַקְתָּ אַחֲרָי׃
כִּי־מִשַּׁשְׁתָּ אֶת־כָּל־כֵּלַי מַה־מָּצָאתָ מִכֹּל כְּלֵי־בֵיתֶךָ שִׂים כֹּה נֶגֶד אַחַי וְאַחֶיךָ וְיוֹכִיחוּ בֵּין שְׁנֵינוּ׃
זֶה עֶשְׂרִים שָׁנָה אָנֹכִי עִמָּךְ רְחֵלֶיךָ וְעִזֶּיךָ לֹא שִׁכֵּלוּ וְאֵילֵי צֹאנְךָ לֹא אָכָלְתִּי׃
טְרֵפָה לֹא־הֵבֵאתִי אֵלֶיךָ אָנֹכִי אֲחַטֶּנָּה מִיָּדִי תְּבַקְשֶׁנָּה גְּנֻבְתִי יוֹם וּגְנֻבְתִי לָיְלָה׃
הָיִיתִי בַיּוֹם אֲכָלַנִי חֹרֶב וְקֶרַח בַּלָּיְלָה וַתִּדַּד שְׁנָתִי מֵעֵינָי׃
זֶה־לִּי עֶשְׂרִים שָׁנָה בְּבֵיתֶךָ עֲבַדְתִּיךָ אַרְבַּע־עֶשְׂרֵה שָׁנָה בִּשְׁתֵּי בְנֹתֶיךָ וְשֵׁשׁ שָׁנִים בְּצֹאנֶךָ וַתַּחֲלֵף אֶת־מַשְׂכֻּרְתִּי עֲשֶׂרֶת מֹנִים׃
לוּלֵי אֱלֹהֵי אָבִי אֱלֹהֵי אַבְרָהָם וּפַחַד יִצְחָק הָיָה לִי כִּי עַתָּה רֵיקָם שִׁלַּחְתָּנִי אֶת־עָנְיִי וְאֶת־יְגִיעַ כַּפַּי רָאָה אֱלֹהִים וַיּוֹכַח אָמֶשׁ׃
וַיַּעַן לָבָן וַיֹּאמֶר אֶל־יַעֲקֹב הַבָּנוֹת בְּנֹתַי וְהַבָּנִים בָּנַי וְהַצֹּאן צֹאנִי וְכֹל אֲשֶׁר־אַתָּה רֹאֶה לִי־הוּא וְלִבְנֹתַי מָה־אֶעֱשֶׂה לָאֵלֶּה הַיּוֹם אוֹ לִבְנֵיהֶן אֲשֶׁר יָלָדוּ׃
וְעַתָּה לְכָה נִכְרְתָה בְרִית אֲנִי וָאָתָּה וְהָיָה לְעֵד בֵּינִי וּבֵינֶךָ׃
וַיִּקַּח יַעֲקֹב אָבֶן וַיְרִימֶהָ מַצֵּבָה׃
וַיֹּאמֶר יַעֲקֹב לְאֶחָיו לִקְטוּ אֲבָנִים וַיִּקְחוּ אֲבָנִים וַיַּעֲשׂוּ־גָל וַיֹּאכְלוּ שָׁם עַל־הַגָּל׃
וַיִּקְרָא־לוֹ לָבָן יְגַר שָׂהֲדוּתָא וְיַעֲקֹב קָרָא לוֹ גַּלְעֵד׃
וַיֹּאמֶר לָבָן הַגַּל הַזֶּה עֵד בֵּינִי וּבֵינְךָ הַיּוֹם עַל־כֵּן קָרָא־שְׁמוֹ גַּלְעֵד׃
וְהַמִּצְפָּה אֲשֶׁר אָמַר יִצֶף יְהוָה בֵּינִי וּבֵינֶךָ כִּי נִסָּתֵר אִישׁ מֵרֵעֵהוּ׃
אִם־תְּעַנֶּה אֶת־בְּנֹתַי וְאִם־תִּקַּח נָשִׁים עַל־בְּנֹתַי אֵין אִישׁ עִמָּנוּ רְאֵה אֱלֹהִים עֵד בֵּינִי וּבֵינֶךָ׃
וַיֹּאמֶר לָבָן לְיַעֲקֹב הִנֵּה הַגַּל הַזֶּה וְהִנֵּה הַמַצֵּבָה אֲשֶׁר יָרִיתִי בֵּינִי וּבֵינֶךָ׃
עֵד הַגַּל הַזֶּה וְעֵדָה הַמַּצֵּבָה אִם־אָנִי לֹא־אֶעֱבֹר אֵלֶיךָ אֶת־הַגַּל הַזֶּה וְאִם־אַתָּה לֹא־תַעֲבֹר אֵלַי אֶת־הַגַּל הַזֶּה וְאֶת־הַמַּצֵּבָה הַזֹּאת לְרָעָה׃
אֱלֹהֵי אַבְרָהָם וֵאלֹהֵי נָחוֹר יִשְׁפְּטוּ בֵינֵינוּ אֱלֹהֵי אֲבִיהֶם וַיִּשָּׁבַע יַעֲקֹב בְּפַחַד אָבִיו יִצְחָק׃
וַיִּזְבַּח יַעֲקֹב זֶבַח בָּהָר וַיִּקְרָא לְאֶחָיו לֶאֱכָל־לָחֶם וַיֹּאכְלוּ לֶחֶם וַיָּלִינוּ בָּהָר׃

Chapter 32

וַיַּשְׁכֵּם לָבָן בַּבֹּקֶר וַיְנַשֵּׁק לְבָנָיו וְלִבְנוֹתָיו וַיְבָרֶךְ אֶתְהֶם וַיֵּלֶךְ וַיָּשָׁב לָבָן לִמְקֹמוֹ׃
וְיַעֲקֹב הָלַךְ לְדַרְכּוֹ וַיִּפְגְּעוּ־בוֹ מַלְאֲכֵי אֱלֹהִים׃
וַיֹּאמֶר יַעֲקֹב כַּאֲשֶׁר רָאָם מַחֲנֵה אֱלֹהִים זֶה וַיִּקְרָא שֵׁם־הַמָּקוֹם הַהוּא מַחֲנָיִם׃
וַיִּשְׁלַח יַעֲקֹב מַלְאָכִים לְפָנָיו אֶל־עֵשָׂו אָחִיו אַרְצָה שֵׂעִיר שְׂדֵה אֱדוֹם׃
וַיְצַו אֹתָם לֵאמֹר כֹּה תֹאמְרוּן לַאדֹנִי לְעֵשָׂו כֹּה אָמַר עַבְדְּךָ יַעֲקֹב עִם־לָבָן גַּרְתִּי וָאֵחַר עַד־עָתָּה׃
וַיְהִי־לִי שׁוֹר וַחֲמוֹר צֹאן וְעֶבֶד וְשִׁפְחָה וָאֶשְׁלְחָה לְהַגִּיד לַאדֹנִי לִמְצֹא־חֵן בְּעֵינֶיךָ׃
וַיָּשֻׁבוּ הַמַּלְאָכִים אֶל־יַעֲקֹב לֵאמֹר בָּאנוּ אֶל־אָחִיךָ אֶל־עֵשָׂו וְגַם הֹלֵךְ לִקְרָאתְךָ וְאַרְבַּע־מֵאוֹת אִישׁ עִמּוֹ׃
וַיִּירָא יַעֲקֹב מְאֹד וַיֵּצֶר לוֹ וַיַּחַץ אֶת־הָעָם אֲשֶׁר־אִתּוֹ וְאֶת־הַצֹּאן וְאֶת־הַבָּקָר וְהַגְּמַלִּים לִשְׁנֵי מַחֲנוֹת׃
וַיֹּאמֶר אִם־יָבוֹא עֵשָׂו אֶל־הַמַּחֲנֶה הָאַחַת וְהִכָּהוּ וְהָיָה הַמַּחֲנֶה הַנִּשְׁאָר לִפְלֵיטָה׃
וַיֹּאמֶר יַעֲקֹב אֱלֹהֵי אָבִי אַבְרָהָם וֵאלֹהֵי אָבִי יִצְחָק יְהוָה הָאֹמֵר אֵלַי שׁוּב לְאַרְצְךָ וּלְמוֹלַדְתְּךָ וְאֵיטִיבָה עִמָּךְ׃
קָטֹנְתִּי מִכֹּל הַחֲסָדִים וּמִכָּל־הָאֱמֶת אֲשֶׁר עָשִׂיתָ אֶת־עַבְדֶּךָ כִּי בְמַקְלִי עָבַרְתִּי אֶת־הַיַּרְדֵּן הַזֶּה וְעַתָּה הָיִיתִי לִשְׁנֵי מַחֲנוֹת׃
הַצִּילֵנִי נָא מִיַּד אָחִי מִיַּד עֵשָׂו כִּי־יָרֵא אָנֹכִי אֹתוֹ פֶּן־יָבוֹא וְהִכַּנִי אֵם עַל־בָּנִים׃
וְאַתָּה אָמַרְתָּ הֵיטֵב אֵיטִיב עִמָּךְ וְשַׂמְתִּי אֶת־זַרְעֲךָ כְּחוֹל הַיָּם אֲשֶׁר לֹא־יִסָּפֵר מֵרֹב׃
וַיָּלֶן שָׁם בַּלַּיְלָה הַהוּא וַיִּקַּח מִן־הַבָּא בְיָדוֹ מִנְחָה לְעֵשָׂו אָחִיו׃
עִזִּים מָאתַיִם וּתְיָשִׁים עֶשְׂרִים רְחֵלִים מָאתַיִם וְאֵילִים עֶשְׂרִים׃
גְּמַלִּים מֵינִיקוֹת וּבְנֵיהֶם שְׁלֹשִׁים פָּרוֹת אַרְבָּעִים וּפָרִים עֲשָׂרָה אֲתֹנֹת עֶשְׂרִים וַעְיָרִם עֲשָׂרָה׃
וַיִּתֵּן בְּיַד־עֲבָדָיו עֵדֶר עֵדֶר לְבַדּוֹ וַיֹּאמֶר אֶל־עֲבָדָיו עִבְרוּ לְפָנַי וְרֶוַח תָּשִׂימוּ בֵּין עֵדֶר וּבֵין עֵדֶר׃
וַיְצַו אֶת־הָרִאשׁוֹן לֵאמֹר כִּי יִפְגָּשְׁךָ עֵשָׂו אָחִי וִשְׁאֵלְךָ לֵאמֹר לְמִי־אַתָּה וְאָנָה תֵלֵךְ וּלְמִי אֵלֶּה לְפָנֶיךָ׃
וְאָמַרְתָּ לְעַבְדְּךָ לְיַעֲקֹב מִנְחָה הִוא שְׁלוּחָה לַאדֹנִי לְעֵשָׂו וְהִנֵּה גַם־הוּא אַחֲרֵינוּ׃
וַיְצַו גַּם אֶת־הַשֵּׁנִי גַּם אֶת־הַשְּׁלִישִׁי גַּם אֶת־כָּל־הַהֹלְכִים אַחֲרֵי הָעֲדָרִים לֵאמֹר כַּדָּבָר הַזֶּה תְּדַבְּרוּן אֶל־עֵשָׂו בְּמֹצַאֲכֶם אֹתוֹ׃
וַאֲמַרְתֶּם גַּם הִנֵּה עַבְדְּךָ יַעֲקֹב אַחֲרֵינוּ כִּי־אָמַר אֲכַפְּרָה פָנָיו בַּמִּנְחָה הַהֹלֶכֶת לְפָנָי וְאַחֲרֵי־כֵן אֶרְאֶה פָנָיו אוּלַי יִשָּׂא פָנָי׃
וַתַּעֲבֹר הַמִּנְחָה עַל־פָּנָיו וְהוּא לָן בַּלַּיְלָה־הַהוּא בַּמַּחֲנֶה׃
וַיָּקָם בַּלַּיְלָה הוּא וַיִּקַּח אֶת־שְׁתֵּי נָשָׁיו וְאֶת־שְׁתֵּי שִׁפְחֹתָיו וְאֶת־אַחַד עָשָׂר יְלָדָיו וַיַּעֲבֹר אֵת מַעֲבַר יַבֹּק׃
וַיִּקָּחֵם וַיַּעֲבִרֵם אֶת־הַנָּחַל וַיַּעֲבֵר אֶת־אֲשֶׁר־לוֹ׃
וַיִּוָּתֵר יַעֲקֹב לְבַדּוֹ וַיֵּאָבֵק אִישׁ עִמּוֹ עַד עֲלוֹת הַשָּׁחַר׃
וַיַּרְא כִּי לֹא יָכֹל לוֹ וַיִּגַּע בְּכַף־יְרֵכוֹ וַתֵּקַע כַּף־יֶרֶךְ יַעֲקֹב בְּהֵאָבְקוֹ עִמּוֹ׃
וַיֹּאמֶר שַׁלְּחֵנִי כִּי עָלָה הַשָּׁחַר וַיֹּאמֶר לֹא אֲשַׁלֵּחֲךָ כִּי אִם־בֵּרַכְתָּנִי׃
וַיֹּאמֶר אֵלָיו מַה־שְּׁמֶךָ וַיֹּאמֶר יַעֲקֹב׃
וַיֹּאמֶר לֹא יַעֲקֹב יֵאָמֵר עוֹד שִׁמְךָ כִּי אִם־יִשְׂרָאֵל כִּי־שָׂרִיתָ עִם־אֱלֹהִים וְעִם־אֲנָשִׁים וַתּוּכָל׃
וַיִּשְׁאַל יַעֲקֹב וַיֹּאמֶר הַגִּידָה־נָּא שְׁמֶךָ וַיֹּאמֶר לָמָּה זֶּה תִּשְׁאַל לִשְׁמִי וַיְבָרֶךְ אֹתוֹ שָׁם׃
וַיִּקְרָא יַעֲקֹב שֵׁם הַמָּקוֹם פְּנִיאֵל כִּי־רָאִיתִי אֱלֹהִים פָּנִים אֶל־פָּנִים וַתִּנָּצֵל נַפְשִׁי׃
וַיִּזְרַח־לוֹ הַשֶּׁמֶשׁ כַּאֲשֶׁר עָבַר אֶת־פְּנוּאֵל וְהוּא צֹלֵעַ עַל־יְרֵכוֹ׃
עַל־כֵּן לֹא־יֹאכְלוּ בְנֵי־יִשְׂרָאֵל אֶת־גִּיד הַנָּשֶׁה אֲשֶׁר עַל־כַּף הַיָּרֵךְ עַד הַיּוֹם הַזֶּה כִּי נָגַע בְּכַף־יֶרֶךְ יַעֲקֹב בְּגִיד הַנָּשֶׁה׃

Chapter 33

וַיִּשָּׂא יַעֲקֹב עֵינָיו וַיַּרְא וְהִנֵּה עֵשָׂו בָּא וְעִמּוֹ אַרְבַּע מֵאוֹת אִישׁ וַיַּחַץ אֶת־הַיְלָדִים עַל־לֵאָה וְעַל־רָחֵל וְעַל שְׁתֵּי הַשְּׁפָחוֹת׃
וַיָּשֶׂם אֶת־הַשְּׁפָחוֹת וְאֶת־יַלְדֵיהֶן רִאשֹׁנָה וְאֶת־לֵאָה וִילָדֶיהָ אַחֲרֹנִים וְאֶת־רָחֵל וְאֶת־יוֹסֵף אַחֲרֹנִים׃
וְהוּא עָבַר לִפְנֵיהֶם וַיִּשְׁתַּחוּ אַרְצָה שֶׁבַע פְּעָמִים עַד־גִּשְׁתּוֹ עַד־אָחִיו׃
וַיָּרָץ עֵשָׂו לִקְרָאתוֹ וַיְחַבְּקֵהוּ וַיִּפֹּל עַל־צַוָּארָו וַיִּשָּׁקֵהוּ וַיִּבְכּוּ׃
וַיִּשָּׂא אֶת־עֵינָיו וַיַּרְא אֶת־הַנָּשִׁים וְאֶת־הַיְלָדִים וַיֹּאמֶר מִי־אֵלֶּה לָּךְ וַיֹּאמַר הַיְלָדִים אֲשֶׁר־חָנַן אֱלֹהִים אֶת־עַבְדֶּךָ׃
וַתִּגַּשְׁןָ הַשְּׁפָחוֹת הֵנָּה וְיַלְדֵיהֶן וַתִּשְׁתַּחֲוֶיןָ׃
וַתִּגַּשׁ גַּם־לֵאָה וִילָדֶיהָ וַיִּשְׁתַּחֲווּ וְאַחַר נִגַּשׁ יוֹסֵף וְרָחֵל וַיִּשְׁתַּחֲווּ׃
וַיֹּאמֶר מִי לְךָ כָּל־הַמַּחֲנֶה הַזֶּה אֲשֶׁר פָּגָשְׁתִּי וַיֹּאמֶר לִמְצֹא־חֵן בְּעֵינֵי אֲדֹנִי׃
וַיֹּאמֶר עֵשָׂו יֶשׁ־לִי רָב אָחִי יְהִי לְךָ אֲשֶׁר־לָךְ׃
וַיֹּאמֶר יַעֲקֹב אַל־נָא אִם־נָא מָצָאתִי חֵן בְּעֵינֶיךָ וְלָקַחְתָּ מִנְחָתִי מִיָּדִי כִּי עַל־כֵּן רָאִיתִי פָנֶיךָ כִּרְאֹת פְּנֵי אֱלֹהִים וַתִּרְצֵנִי׃
קַח־נָא אֶת־בִּרְכָתִי אֲשֶׁר הֻבָאת לָךְ כִּי־חַנַּנִי אֱלֹהִים וְכִי יֶשׁ־לִי־כֹל וַיִּפְצַר־בּוֹ וַיִּקָּח׃
וַיֹּאמֶר נִסְעָה וְנֵלֵכָה וְאֵלְכָה לְנֶגְדֶּךָ׃
וַיֹּאמֶר אֵלָיו אֲדֹנִי יֹדֵעַ כִּי־הַיְלָדִים רַכִּים וְהַצֹּאן וְהַבָּקָר עָלוֹת עָלָי וּדְפָקוּם יוֹם אֶחָד וָמֵתוּ כָּל־הַצֹּאן׃
יַעֲבָר־נָא אֲדֹנִי לִפְנֵי עַבְדּוֹ וַאֲנִי אֶתְנָהֲלָה לְאִטִּי לְרֶגֶל הַמְּלָאכָה אֲשֶׁר־לְפָנַי וּלְרֶגֶל הַיְלָדִים עַד אֲשֶׁר־אָבֹא אֶל־אֲדֹנִי שֵׂעִירָה׃
וַיֹּאמֶר עֵשָׂו אַצִּיגָה־נָּא עִמְּךָ מִן־הָעָם אֲשֶׁר אִתִּי וַיֹּאמֶר לָמָּה זֶּה אֶמְצָא־חֵן בְּעֵינֵי אֲדֹנִי׃
וַיָּשָׁב בַּיּוֹם הַהוּא עֵשָׂו לְדַרְכּוֹ שֵׂעִירָה׃
וְיַעֲקֹב נָסַע סֻכֹּתָה וַיִּבֶן לוֹ בָּיִת וּלְמִקְנֵהוּ עָשָׂה סֻכֹּת עַל־כֵּן קָרָא שֵׁם־הַמָּקוֹם סֻכּוֹת׃
וַיָּבֹא יַעֲקֹב שָׁלֵם עִיר שְׁכֶם אֲשֶׁר בְּאֶרֶץ כְּנַעַן בְּבֹאוֹ מִפַּדַּן אֲרָם וַיִּחַן אֶת־פְּנֵי הָעִיר׃
וַיִּקֶן אֶת־חֶלְקַת הַשָּׂדֶה אֲשֶׁר נָטָה־שָׁם אָהֳלוֹ מִיַּד בְּנֵי־חֲמוֹר אֲבִי שְׁכֶם בְּמֵאָה קְשִׂיטָה׃
וַיַּצֶּב־שָׁם מִזְבֵּחַ וַיִּקְרָא־לוֹ אֵל אֱלֹהֵי יִשְׂרָאֵל׃

Chapter 34

וַתֵּצֵא דִינָה בַּת־לֵאָה אֲשֶׁר יָלְדָה לְיַעֲקֹב לִרְאוֹת בִּבְנוֹת הָאָרֶץ׃
וַיַּרְא אֹתָהּ שְׁכֶם בֶּן־חֲמוֹר הַחִוִּי נְשִׂיא הָאָרֶץ וַיִּקַּח אֹתָהּ וַיִּשְׁכַּב אֹתָהּ וַיְעַנֶּהָ׃
וַתִּדְבַּק נַפְשׁוֹ בְּדִינָה בַּת־יַעֲקֹב וַיֶּאֱהַב אֶת־הַנַּעֲרָ וַיְדַבֵּר עַל־לֵב הַנַּעֲרָ׃
וַיֹּאמֶר שְׁכֶם אֶל־חֲמוֹר אָבִיו לֵאמֹר קַח־לִי אֶת־הַיַּלְדָּה הַזֹּאת לְאִשָּׁה׃
וְיַעֲקֹב שָׁמַע כִּי טִמֵּא אֶת־דִּינָה בִתּוֹ וּבָנָיו הָיוּ אֶת־מִקְנֵהוּ בַּשָּׂדֶה וְהֶחֱרִשׁ יַעֲקֹב עַד־בֹּאָם׃
וַיֵּצֵא חֲמוֹר אֲבִי־שְׁכֶם אֶל־יַעֲקֹב לְדַבֵּר אִתּוֹ׃
וּבְנֵי יַעֲקֹב בָּאוּ מִן־הַשָּׂדֶה כְּשָׁמְעָם וַיִּתְעַצְּבוּ הָאֲנָשִׁים וַיִּחַר לָהֶם מְאֹד כִּי־נְבָלָה עָשָׂה בְיִשְׂרָאֵל לִשְׁכַּב אֶת־בַּת־יַעֲקֹב וְכֵן לֹא יֵעָשֶׂה׃
וַיְדַבֵּר חֲמוֹר אִתָּם לֵאמֹר שְׁכֶם בְּנִי חָשְׁקָה נַפְשׁוֹ בְּבִתְּכֶם תְּנוּ נָא אֹתָהּ לוֹ לְאִשָּׁה׃
וְהִתְחַתְּנוּ אֹתָנוּ בְּנֹתֵיכֶם תִּתְּנוּ־לָנוּ וְאֶת־בְּנֹתֵינוּ תִּקְחוּ לָכֶם׃
וְאִתָּנוּ תֵּשֵׁבוּ וְהָאָרֶץ תִּהְיֶה לִפְנֵיכֶם שְׁבוּ וּסְחָרוּהָ וְהֵאָחֲזוּ בָּהּ׃
וַיֹּאמֶר שְׁכֶם אֶל־אָבִיה וְאֶל־אַחֶיהָ אֶמְצָא־חֵן בְּעֵינֵיכֶם וַאֲשֶׁר תֹּאמְרוּ אֵלַי אֶתֵּן׃
הַרְבּוּ עָלַי מְאֹד מֹהַר וּמַתָּן וְאֶתְּנָה כַּאֲשֶׁר תֹּאמְרוּ אֵלָי וּתְנוּ־לִי אֶת־הַנַּעֲרָ לְאִשָּׁה׃
וַיַּעֲנוּ בְנֵי־יַעֲקֹב אֶת־שְׁכֶם וְאֶת־חֲמוֹר אָבִיו בְּמִרְמָה וַיְדַבֵּרוּ אֲשֶׁר טִמֵּא אֵת דִּינָה אֲחֹתָם׃
וַיֹּאמְרוּ אֲלֵיהֶם לֹא נוּכַל לַעֲשׂוֹת הַדָּבָר הַזֶּה לָתֵת אֶת־אֲחֹתֵנוּ לְאִישׁ אֲשֶׁר־לוֹ עָרְלָה כִּי־חֶרְפָּה הִוא לָנוּ׃
אַךְ־בְּזֹאת נֵאוֹת לָכֶם אִם תִּהְיוּ כָמֹנוּ לְהִמֹּל לָכֶם כָּל־זָכָר׃
וְנָתַנּוּ אֶת־בְּנֹתֵינוּ לָכֶם וְאֶת־בְּנֹתֵיכֶם נִקַּח־לָנוּ וְיָשַׁבְנוּ אִתְּכֶם וְהָיִינוּ לְעַם אֶחָד׃
וְאִם־לֹא תִשְׁמְעוּ אֵלֵינוּ לְהִמּוֹל וְלָקַחְנוּ אֶת־בִּתֵּנוּ וְהָלָכְנוּ׃
וַיִּיטְבוּ דִבְרֵיהֶם בְּעֵינֵי חֲמוֹר וּבְעֵינֵי שְׁכֶם בֶּן־חֲמוֹר׃
וְלֹא־אֵחַר הַנַּעַר לַעֲשׂוֹת הַדָּבָר כִּי חָפֵץ בְּבַת־יַעֲקֹב וְהוּא נִכְבָּד מִכֹּל בֵּית אָבִיו׃
וַיָּבֹא חֲמוֹר וּשְׁכֶם בְּנוֹ אֶל־שַׁעַר עִירָם וַיְדַבְּרוּ אֶל־אַנְשֵׁי עִירָם לֵאמֹר׃
הָאֲנָשִׁים הָאֵלֶּה שְׁלֵמִים הֵם אִתָּנוּ וְיֵשְׁבוּ בָאָרֶץ וְיִסְחֲרוּ אֹתָהּ וְהָאָרֶץ הִנֵּה רַחֲבַת־יָדַיִם לִפְנֵיהֶם אֶת־בְּנֹתָם נִקַּח־לָנוּ לְנָשִׁים וְאֶת־בְּנֹתֵינוּ נִתֵּן לָהֶם׃
אַךְ־בְּזֹאת יֵאֹתוּ לָנוּ הָאֲנָשִׁים לָשֶׁבֶת אִתָּנוּ לִהְיוֹת לְעַם אֶחָד בְּהִמּוֹל לָנוּ כָּל־זָכָר כַּאֲשֶׁר הֵם נִמֹּלִים׃
מִקְנֵהֶם וְקִנְיָנָם וְכָל־בְּהֶמְתָּם הֲלוֹא לָנוּ הֵם אַךְ נֵאוֹתָה לָהֶם וְיֵשְׁבוּ אִתָּנוּ׃
וַיִּשְׁמְעוּ אֶל־חֲמוֹר וְאֶל־שְׁכֶם בְּנוֹ כָּל־יֹצְאֵי שַׁעַר עִירוֹ וַיִּמֹּלוּ כָּל־זָכָר כָּל־יֹצְאֵי שַׁעַר עִירוֹ׃
וַיְהִי בַיּוֹם הַשְּׁלִישִׁי בִּהְיוֹתָם כֹּאֲבִים וַיִּקְחוּ שְׁנֵי־בְנֵי־יַעֲקֹב שִׁמְעוֹן וְלֵוִי אֲחֵי דִינָה אִישׁ חַרְבּוֹ וַיָּבֹאוּ עַל־הָעִיר בֶּטַח וַיַּהַרְגוּ כָּל־זָכָר׃
וְאֶת־חֲמוֹר וְאֶת־שְׁכֶם בְּנוֹ הָרְגוּ לְפִי־חָרֶב וַיִּקְחוּ אֶת־דִּינָה מִבֵּית שְׁכֶם וַיֵּצֵאוּ׃
בְּנֵי יַעֲקֹב בָּאוּ עַל־הַחֲלָלִים וַיָּבֹזּוּ הָעִיר אֲשֶׁר טִמְּאוּ אֲחוֹתָם׃
אֶת־צֹאנָם וְאֶת־בְּקָרָם וְאֶת־חֲמֹרֵיהֶּם וְאֵת אֲשֶׁר־בָּעִיר וְאֶת־אֲשֶׁר בַּשָּׂדֶה לָקָחוּ׃
וְאֶת־כָּל־חֵילָם וְאֶת־כָּל־טַפָּם וְאֶת־נְשֵׁיהֶם שָׁבוּ וַיָּבֹזּוּ וְאֵת כָּל־אֲשֶׁר בַּבָּיִת׃
וַיֹּאמֶר יַעֲקֹב אֶל־שִׁמְעוֹן וְאֶל־לֵוִי עֲכַרְתֶּם אֹתִי לְהַבְאִישֵׁנִי בְּיֹשֵׁב הָאָרֶץ בַּכְּנַעֲנִי וּבַפְּרִזִּי וַאֲנִי מְתֵי מִסְפָּר וְנֶאֶסְפוּ עָלַי וְהִכּוּנִי וְנִשְׁמַדְתִּי אֲנִי וּבֵיתִי׃
וַיֹּאמְרוּ הַכְזוֹנָה יַעֲשֶׂה אֶת־אֲחוֹתֵנוּ׃

Chapter 35

וַיֹּאמֶר אֱלֹהִים אֶל־יַעֲקֹב קוּם עֲלֵה בֵית־אֵל וְשֶׁב־שָׁם וַעֲשֵׂה־שָׁם מִזְבֵּחַ לָאֵל הַנִּרְאֶה אֵלֶיךָ בְּבָרְחֲךָ מִפְּנֵי עֵשָׂו אָחִיךָ׃
וַיֹּאמֶר יַעֲקֹב אֶל־בֵּיתוֹ וְאֶל כָּל־אֲשֶׁר עִמּוֹ הָסִרוּ אֶת־אֱלֹהֵי הַנֵּכָר אֲשֶׁר בְּתֹכְכֶם וְהִטַּהֲרוּ וְהַחֲלִיפוּ שִׂמְלֹתֵיכֶם׃
וְנָקוּמָה וְנַעֲלֶה בֵּית־אֵל וְאֶעֱשֶׂה־שָּׁם מִזְבֵּחַ לָאֵל הָעֹנֶה אֹתִי בְּיוֹם צָרָתִי וַיְהִי עִמָּדִי בַּדֶּרֶךְ אֲשֶׁר הָלָכְתִּי׃
וַיִּתְּנוּ אֶל־יַעֲקֹב אֵת כָּל־אֱלֹהֵי הַנֵּכָר אֲשֶׁר בְּיָדָם וְאֶת־הַנְּזָמִים אֲשֶׁר בְּאָזְנֵיהֶם וַיִּטְמֹן אֹתָם יַעֲקֹב תַּחַת הָאֵלָה אֲשֶׁר עִם־שְׁכֶם׃
וַיִּסָּעוּ וַיְהִי חִתַּת אֱלֹהִים עַל־הֶעָרִים אֲשֶׁר סְבִיבֹתֵיהֶם וְלֹא רָדְפוּ אַחֲרֵי בְּנֵי יַעֲקֹב׃
וַיָּבֹא יַעֲקֹב לוּזָה אֲשֶׁר בְּאֶרֶץ כְּנַעַן הִוא בֵּית־אֵל הוּא וְכָל־הָעָם אֲשֶׁר־עִמּוֹ׃
וַיִּבֶן שָׁם מִזְבֵּחַ וַיִּקְרָא לַמָּקוֹם אֵל בֵּית־אֵל כִּי שָׁם נִגְלוּ אֵלָיו הָאֱלֹהִים בְּבָרְחוֹ מִפְּנֵי אָחִיו׃
וַתָּמָת דְּבֹרָה מֵינֶקֶת רִבְקָה וַתִּקָּבֵר מִתַּחַת לְבֵית־אֵל תַּחַת הָאַלּוֹן וַיִּקְרָא שְׁמוֹ אַלּוֹן בָּכוּת׃
וַיֵּרָא אֱלֹהִים אֶל־יַעֲקֹב עוֹד בְּבֹאוֹ מִפַּדַּן אֲרָם וַיְבָרֶךְ אֹתוֹ׃
וַיֹּאמֶר־לוֹ אֱלֹהִים שִׁמְךָ יַעֲקֹב לֹא־יִקָּרֵא שִׁמְךָ עוֹד יַעֲקֹב כִּי אִם־יִשְׂרָאֵל יִהְיֶה שְׁמֶךָ וַיִּקְרָא אֶת־שְׁמוֹ יִשְׂרָאֵל׃
וַיֹּאמֶר לוֹ אֱלֹהִים אֲנִי אֵל שַׁדַּי פְּרֵה וּרְבֵה גּוֹי וּקְהַל גּוֹיִם יִהְיֶה מִמֶּךָּ וּמְלָכִים מֵחֲלָצֶיךָ יֵצֵאוּ׃
וְאֶת־הָאָרֶץ אֲשֶׁר נָתַתִּי לְאַבְרָהָם וּלְיִצְחָק לְךָ אֶתְּנֶנָּה וּלְזַרְעֲךָ אַחֲרֶיךָ אֶתֵּן אֶת־הָאָרֶץ׃
וַיַּעַל מֵעָלָיו אֱלֹהִים בַּמָּקוֹם אֲשֶׁר־דִּבֶּר אִתּוֹ׃
וַיַּצֵּב יַעֲקֹב מַצֵּבָה בַּמָּקוֹם אֲשֶׁר־דִּבֶּר אִתּוֹ מַצֶּבֶת אָבֶן וַיַּסֵּךְ עָלֶיהָ נֶסֶךְ וַיִּצֹק עָלֶיהָ שָׁמֶן׃
וַיִּקְרָא יַעֲקֹב אֶת־שֵׁם הַמָּקוֹם אֲשֶׁר דִּבֶּר אִתּוֹ שָׁם אֱלֹהִים בֵּית־אֵל׃
וַיִּסְעוּ מִבֵּית אֵל וַיְהִי־עוֹד כִּבְרַת־הָאָרֶץ לָבוֹא אֶפְרָתָה וַתֵּלֶד רָחֵל וַתְּקַשׁ בְּלִדְתָּהּ׃
וַיְהִי בְהַקְשֹׁתָהּ בְּלִדְתָּהּ וַתֹּאמֶר לָהּ הַמְיַלֶּדֶת אַל־תִּירְאִי כִּי־גַם־זֶה לָךְ בֵּן׃
וַיְהִי בְּצֵאת נַפְשָׁהּ כִּי מֵתָה וַתִּקְרָא שְׁמוֹ בֶּן־אוֹנִי וְאָבִיו קָרָא־לוֹ בִנְיָמִין׃
וַתָּמָת רָחֵל וַתִּקָּבֵר בְּדֶרֶךְ אֶפְרָתָה הִוא בֵּית לָחֶם׃
וַיַּצֵּב יַעֲקֹב מַצֵּבָה עַל־קְבֻרָתָהּ הִוא מַצֶּבֶת קְבֻרַת־רָחֵל עַד־הַיּוֹם׃
וַיִּסַּע יִשְׂרָאֵל וַיֵּט אָהֳלֹה מֵהָלְאָה לְמִגְדַּל־עֵדֶר׃
וַיְהִי בִּשְׁכֹּן יִשְׂרָאֵל בָּאָרֶץ הַהִוא וַיֵּלֶךְ רְאוּבֵן וַיִּשְׁכַּב אֶת־בִּלְהָה פִּילֶגֶשׁ אָבִיו וַיִּשְׁמַע יִשְׂרָאֵל וַיִּהְיוּ בְנֵי־יַעֲקֹב שְׁנֵים עָשָׂר׃
בְּנֵי לֵאָה בְּכוֹר יַעֲקֹב רְאוּבֵן וְשִׁמְעוֹן וְלֵוִי וִיהוּדָה וְיִשָּׂשכָר וּזְבוּלֻן׃
בְּנֵי רָחֵל יוֹסֵף וּבִנְיָמִן׃
וּבְנֵי בִלְהָה שִׁפְחַת רָחֵל דָּן וְנַפְתָּלִי׃
וּבְנֵי זִלְפָּה שִׁפְחַת לֵאָה גָּד וְאָשֵׁר אֵלֶּה בְּנֵי יַעֲקֹב אֲשֶׁר יֻלַּד־לוֹ בְּפַדַּן אֲרָם׃
וַיָּבֹא יַעֲקֹב אֶל־יִצְחָק אָבִיו מַמְרֵא קִרְיַת הָאַרְבַּע הִוא חֶבְרוֹן אֲשֶׁר־גָּר־שָׁם אַבְרָהָם וְיִצְחָק׃
וַיִּהְיוּ יְמֵי יִצְחָק מְאַת שָׁנָה וּשְׁמֹנִים שָׁנָה׃
וַיִּגְוַע יִצְחָק וַיָּמָת וַיֵּאָסֶף אֶל־עַמָּיו זָקֵן וּשְׂבַע יָמִים וַיִּקְבְּרוּ אֹתוֹ עֵשָׂו וְיַעֲקֹב בָּנָיו׃

Chapter 36

וְאֵלֶּה תֹּלְדוֹת עֵשָׂו הוּא אֱדוֹם׃
עֵשָׂו לָקַח אֶת־נָשָׁיו מִבְּנוֹת כְּנָעַן אֶת־עָדָה בַּת־אֵילוֹן הַחִתִּי וְאֶת־אָהֳלִיבָמָה בַּת־עֲנָה בַּת־צִבְעוֹן הַחִוִּי׃
וְאֶת־בָּשְׂמַת בַּת־יִשְׁמָעֵאל אֲחוֹת נְבָיוֹת׃
וַתֵּלֶד עָדָה לְעֵשָׂו אֶת־אֱלִיפָז וּבָשְׂמַת יָלְדָה אֶת־רְעוּאֵל׃
וְאָהֳלִיבָמָה יָלְדָה אֶת־יעיש [יְעוּשׁ] וְאֶת־יַעְלָם וְאֶת־קֹרַח אֵלֶּה בְּנֵי עֵשָׂו אֲשֶׁר יֻלְּדוּ־לוֹ בְּאֶרֶץ כְּנָעַן׃
וַיִּקַּח עֵשָׂו אֶת־נָשָׁיו וְאֶת־בָּנָיו וְאֶת־בְּנֹתָיו וְאֶת־כָּל־נַפְשׁוֹת בֵּיתוֹ וְאֶת־מִקְנֵהוּ וְאֶת־כָּל־בְּהֶמְתּוֹ וְאֵת כָּל־קִנְיָנוֹ אֲשֶׁר רָכַשׁ בְּאֶרֶץ כְּנָעַן וַיֵּלֶךְ אֶל־אֶרֶץ מִפְּנֵי יַעֲקֹב אָחִיו׃
כִּי־הָיָה רְכוּשָׁם רָב מִשֶּׁבֶת יַחְדָּו וְלֹא יָכְלָה אֶרֶץ מְגוּרֵיהֶם לָשֵׂאת אֹתָם מִפְּנֵי מִקְנֵיהֶם׃
וַיֵּשֶׁב עֵשָׂו בְּהַר שֵׂעִיר עֵשָׂו הוּא אֱדוֹם׃
וְאֵלֶּה תֹּלְדוֹת עֵשָׂו אֲבִי אֱדוֹם בְּהַר שֵׂעִיר׃
אֵלֶּה שְׁמוֹת בְּנֵי־עֵשָׂו אֱלִיפַז בֶּן־עָדָה אֵשֶׁת עֵשָׂו רְעוּאֵל בֶּן־בָּשְׂמַת אֵשֶׁת עֵשָׂו׃
וַיִּהְיוּ בְּנֵי אֱלִיפָז תֵּימָן אוֹמָר צְפוֹ וְגַעְתָּם וּקְנַז׃
וְתִמְנַע הָיְתָה פִילֶגֶשׁ לֶאֱלִיפַז בֶּן־עֵשָׂו וַתֵּלֶד לֶאֱלִיפַז אֶת־עֲמָלֵק אֵלֶּה בְּנֵי עָדָה אֵשֶׁת עֵשָׂו׃
וְאֵלֶּה בְּנֵי רְעוּאֵל נַחַת וָזֶרַח שַׁמָּה וּמִזָּה אֵלֶּה הָיוּ בְּנֵי בָשְׂמַת אֵשֶׁת עֵשָׂו׃
וְאֵלֶּה הָיוּ בְּנֵי אָהֳלִיבָמָה בַת־עֲנָה בַּת־צִבְעוֹן אֵשֶׁת עֵשָׂו וַתֵּלֶד לְעֵשָׂו אֶת־יעיש [יְעוּשׁ] וְאֶת־יַעְלָם וְאֶת־קֹרַח׃
אֵלֶּה אַלּוּפֵי בְנֵי־עֵשָׂו בְּנֵי אֱלִיפַז בְּכוֹר עֵשָׂו אַלּוּף תֵּימָן אַלּוּף אוֹמָר אַלּוּף צְפוֹ אַלּוּף קְנַז׃
אַלּוּף־קֹרַח אַלּוּף גַּעְתָּם אַלּוּף עֲמָלֵק אֵלֶּה אַלּוּפֵי אֱלִיפַז בְּאֶרֶץ אֱדוֹם אֵלֶּה בְּנֵי עָדָה׃
וְאֵלֶּה בְּנֵי רְעוּאֵל בֶּן־עֵשָׂו אַלּוּף נַחַת אַלּוּף זֶרַח אַלּוּף שַׁמָּה אַלּוּף מִזָּה אֵלֶּה אַלּוּפֵי רְעוּאֵל בְּאֶרֶץ אֱדוֹם אֵלֶּה בְּנֵי בָשְׂמַת אֵשֶׁת עֵשָׂו׃
וְאֵלֶּה בְּנֵי אָהֳלִיבָמָה אֵשֶׁת עֵשָׂו אַלּוּף יְעוּשׁ אַלּוּף יַעְלָם אַלּוּף קֹרַח אֵלֶּה אַלּוּפֵי אָהֳלִיבָמָה בַּת־עֲנָה אֵשֶׁת עֵשָׂו׃
אֵלֶּה בְנֵי־עֵשָׂו וְאֵלֶּה אַלּוּפֵיהֶם הוּא אֱדוֹם׃
אֵלֶּה בְנֵי־שֵׂעִיר הַחֹרִי יֹשְׁבֵי הָאָרֶץ לוֹטָן וְשׁוֹבָל וְצִבְעוֹן וַעֲנָה׃
וְדִשׁוֹן וְאֵצֶר וְדִישָׁן אֵלֶּה אַלּוּפֵי הַחֹרִי בְּנֵי שֵׂעִיר בְּאֶרֶץ אֱדוֹם׃
וַיִּהְיוּ בְנֵי־לוֹטָן חֹרִי וְהֵימָם וַאֲחוֹת לוֹטָן תִּמְנָע׃
וְאֵלֶּה בְּנֵי שׁוֹבָל עַלְוָן וּמָנַחַת וְעֵיבָל שְׁפוֹ וְאוֹנָם׃
וְאֵלֶּה בְנֵי־צִבְעוֹן וְאַיָּה וַעֲנָה הוּא עֲנָה אֲשֶׁר מָצָא אֶת־הַיֵּמִם בַּמִּדְבָּר בִּרְעֹתוֹ אֶת־הַחֲמֹרִים לְצִבְעוֹן אָבִיו׃
וְאֵלֶּה בְנֵי־עֲנָה דִּשֹׁן וְאָהֳלִיבָמָה בַּת־עֲנָה׃
וְאֵלֶּה בְּנֵי דִישָׁן חֶמְדָּן וְאֶשְׁבָּן וְיִתְרָן וּכְרָן׃
אֵלֶּה בְּנֵי־אֵצֶר בִּלְהָן וְזַעֲוָן וַעֲקָן׃
אֵלֶּה בְנֵי־דִישָׁן עוּץ וַאֲרָן׃
אֵלֶּה אַלּוּפֵי הַחֹרִי אַלּוּף לוֹטָן אַלּוּף שׁוֹבָל אַלּוּף צִבְעוֹן אַלּוּף עֲנָה׃
אַלּוּף דִּשֹׁן אַלּוּף אֵצֶר אַלּוּף דִּישָׁן אֵלֶּה אַלּוּפֵי הַחֹרִי לְאַלֻּפֵיהֶם בְּאֶרֶץ שֵׂעִיר׃
וְאֵלֶּה הַמְּלָכִים אֲשֶׁר מָלְכוּ בְּאֶרֶץ אֱדוֹם לִפְנֵי מְלָךְ־מֶלֶךְ לִבְנֵי יִשְׂרָאֵל׃
וַיִּמְלֹךְ בֶּאֱדוֹם בֶּלַע בֶּן־בְּעוֹר וְשֵׁם עִירוֹ דִּנְהָבָה׃
וַיָּמָת בָּלַע וַיִּמְלֹךְ תַּחְתָּיו יוֹבָב בֶּן־זֶרַח מִבָּצְרָה׃
וַיָּמָת יוֹבָב וַיִּמְלֹךְ תַּחְתָּיו חֻשָׁם מֵאֶרֶץ הַתֵּימָנִי׃
וַיָּמָת חֻשָׁם וַיִּמְלֹךְ תַּחְתָּיו הֲדַד בֶּן־בְּדַד הַמַּכֶּה אֶת־מִדְיָן בִּשְׂדֵה מוֹאָב וְשֵׁם עִירוֹ עֲוִית׃
וַיָּמָת הֲדָד וַיִּמְלֹךְ תַּחְתָּיו שַׂמְלָה מִמַּשְׂרֵקָה׃
וַיָּמָת שַׂמְלָה וַיִּמְלֹךְ תַּחְתָּיו שָׁאוּל מֵרְחֹבוֹת הַנָּהָר׃
וַיָּמָת שָׁאוּל וַיִּמְלֹךְ תַּחְתָּיו בַּעַל חָנָן בֶּן־עַכְבּוֹר׃
וַיָּמָת בַּעַל חָנָן בֶּן־עַכְבּוֹר וַיִּמְלֹךְ תַּחְתָּיו הֲדַר וְשֵׁם עִירוֹ פָּעוּ וְשֵׁם אִשְׁתּוֹ מְהֵיטַבְאֵל בַּת־מַטְרֵד בַּת מֵי זָהָב׃
וְאֵלֶּה שְׁמוֹת אַלּוּפֵי עֵשָׂו לְמִשְׁפְּחֹתָם לִמְקֹמֹתָם בִּשְׁמֹתָם אַלּוּף תִּמְנָע אַלּוּף עַלְוָה אַלּוּף יְתֵת׃
אַלּוּף אָהֳלִיבָמָה אַלּוּף אֵלָה אַלּוּף פִּינֹן׃
אַלּוּף קְנַז אַלּוּף תֵּימָן אַלּוּף מִבְצָר׃
אַלּוּף מַגְדִּיאֵל אַלּוּף עִירָם אֵלֶּה אַלּוּפֵי אֱדוֹם לְמֹשְׁבֹתָם בְּאֶרֶץ אֲחֻזָּתָם הוּא עֵשָׂו אֲבִי אֱדוֹם׃

Chapter 37

וַיֵּשֶׁב יַעֲקֹב בְּאֶרֶץ מְגוּרֵי אָבִיו בְּאֶרֶץ כְּנָעַן׃
אֵלֶּה תֹּלְדוֹת יַעֲקֹב יוֹסֵף בֶּן־שְׁבַע־עֶשְׂרֵה שָׁנָה הָיָה רֹעֶה אֶת־אֶחָיו בַּצֹּאן וְהוּא נַעַר אֶת־בְּנֵי בִלְהָה וְאֶת־בְּנֵי זִלְפָּה נְשֵׁי אָבִיו וַיָּבֵא יוֹסֵף אֶת־דִּבָּתָם רָעָה אֶל־אֲבִיהֶם׃
וְיִשְׂרָאֵל אָהַב אֶת־יוֹסֵף מִכָּל־בָּנָיו כִּי־בֶן־זְקֻנִים הוּא לוֹ וְעָשָׂה לוֹ כְּתֹנֶת פַּסִּים׃
וַיִּרְאוּ אֶחָיו כִּי־אֹתוֹ אָהַב אֲבִיהֶם מִכָּל־אֶחָיו וַיִּשְׂנְאוּ אֹתוֹ וְלֹא יָכְלוּ דַּבְּרוֹ לְשָׁלֹם׃
וַיַּחֲלֹם יוֹסֵף חֲלוֹם וַיַּגֵּד לְאֶחָיו וַיּוֹסִפוּ עוֹד שְׂנֹא אֹתוֹ׃
וַיֹּאמֶר אֲלֵיהֶם שִׁמְעוּ־נָא הַחֲלוֹם הַזֶּה אֲשֶׁר חָלָמְתִּי׃
וְהִנֵּה אֲנַחְנוּ מְאַלְּמִים אֲלֻמִּים בְּתוֹךְ הַשָּׂדֶה וְהִנֵּה קָמָה אֲלֻמָּתִי וְגַם־נִצָּבָה וְהִנֵּה תְסֻבֶּינָה אֲלֻמֹּתֵיכֶם וַתִּשְׁתַּחֲוֶיןָ לַאֲלֻמָּתִי׃
וַיֹּאמְרוּ לוֹ אֶחָיו הֲמָלֹךְ תִּמְלֹךְ עָלֵינוּ אִם־מָשׁוֹל תִּמְשֹׁל בָּנוּ וַיּוֹסִפוּ עוֹד שְׂנֹא אֹתוֹ עַל־חֲלֹמֹתָיו וְעַל־דְּבָרָיו׃
וַיַּחֲלֹם עוֹד חֲלוֹם אַחֵר וַיְסַפֵּר אֹתוֹ לְאֶחָיו וַיֹּאמֶר הִנֵּה חָלַמְתִּי חֲלוֹם עוֹד וְהִנֵּה הַשֶּׁמֶשׁ וְהַיָּרֵחַ וְאַחַד עָשָׂר כּוֹכָבִים מִשְׁתַּחֲוִים לִי׃
וַיְסַפֵּר אֶל־אָבִיו וְאֶל־אֶחָיו וַיִּגְעַר־בּוֹ אָבִיו וַיֹּאמֶר לוֹ מָה הַחֲלוֹם הַזֶּה אֲשֶׁר חָלָמְתָּ הֲבוֹא נָבוֹא אֲנִי וְאִמְּךָ וְאַחֶיךָ לְהִשְׁתַּחֲוֺת לְךָ אָרְצָה׃
וַיְקַנְאוּ־בוֹ אֶחָיו וְאָבִיו שָׁמַר אֶת־הַדָּבָר׃
וַיֵּלְכוּ אֶחָיו לִרְעוֹת אֶת־צֹאן אֲבִיהֶם בִּשְׁכֶם׃
וַיֹּאמֶר יִשְׂרָאֵל אֶל־יוֹסֵף הֲלוֹא אַחֶיךָ רֹעִים בִּשְׁכֶם לְכָה וְאֶשְׁלָחֲךָ אֲלֵיהֶם וַיֹּאמֶר לוֹ הִנֵּנִי׃
וַיֹּאמֶר לוֹ לֶךְ־נָא רְאֵה אֶת־שְׁלוֹם אַחֶיךָ וְאֶת־שְׁלוֹם הַצֹּאן וַהֲשִׁבֵנִי דָּבָר וַיִּשְׁלָחֵהוּ מֵעֵמֶק חֶבְרוֹן וַיָּבֹא שְׁכֶמָה׃
וַיִּמְצָאֵהוּ אִישׁ וְהִנֵּה תֹעֶה בַּשָּׂדֶה וַיִּשְׁאָלֵהוּ הָאִישׁ לֵאמֹר מַה־תְּבַקֵּשׁ׃
וַיֹּאמֶר אֶת־אַחַי אָנֹכִי מְבַקֵּשׁ הַגִּידָה־נָּא לִי אֵיפֹה הֵם רֹעִים׃
וַיֹּאמֶר הָאִישׁ נָסְעוּ מִזֶּה כִּי שָׁמַעְתִּי אֹמְרִים נֵלְכָה דֹּתָיְנָה וַיֵּלֶךְ יוֹסֵף אַחַר אֶחָיו וַיִּמְצָאֵם בְּדֹתָן׃
וַיִּרְאוּ אֹתוֹ מֵרָחֹק וּבְטֶרֶם יִקְרַב אֲלֵיהֶם וַיִּתְנַכְּלוּ אֹתוֹ לַהֲמִיתוֹ׃
וַיֹּאמְרוּ אִישׁ אֶל־אָחִיו הִנֵּה בַּעַל הַחֲלֹמוֹת הַלָּזֶה בָּא׃
וְעַתָּה לְכוּ וְנַהַרְגֵהוּ וְנַשְׁלִכֵהוּ בְּאַחַד הַבֹּרוֹת וְאָמַרְנוּ חַיָּה רָעָה אֲכָלָתְהוּ וְנִרְאֶה מַה־יִּהְיוּ חֲלֹמֹתָיו׃
וַיִּשְׁמַע רְאוּבֵן וַיַּצִּלֵהוּ מִיָּדָם וַיֹּאמֶר לֹא נַכֶּנּוּ נָפֶשׁ׃
וַיֹּאמֶר אֲלֵהֶם רְאוּבֵן אַל־תִּשְׁפְּכוּ־דָם הַשְׁלִיכוּ אֹתוֹ אֶל־הַבּוֹר הַזֶּה אֲשֶׁר בַּמִּדְבָּר וְיָד אַל־תִּשְׁלְחוּ־בוֹ לְמַעַן הַצִּיל אֹתוֹ מִיָּדָם לַהֲשִׁיבוֹ אֶל־אָבִיו׃
וַיְהִי כַּאֲשֶׁר־בָּא יוֹסֵף אֶל־אֶחָיו וַיַּפְשִׁיטוּ אֶת־יוֹסֵף אֶת־כֻּתָּנְתּוֹ אֶת־כְּתֹנֶת הַפַּסִּים אֲשֶׁר עָלָיו׃
וַיִּקָּחֻהוּ וַיַּשְׁלִכוּ אֹתוֹ הַבֹּרָה וְהַבּוֹר רֵק אֵין בּוֹ מָיִם׃
וַיֵּשְׁבוּ לֶאֱכָל־לֶחֶם וַיִּשְׂאוּ עֵינֵיהֶם וַיִּרְאוּ וְהִנֵּה אֹרְחַת יִשְׁמְעֵאלִים בָּאָה מִגִּלְעָד וּגְמַלֵּיהֶם נֹשְׂאִים נְכֹאת וּצְרִי וָלֹט הוֹלְכִים לְהוֹרִיד מִצְרָיְמָה׃
וַיֹּאמֶר יְהוּדָה אֶל־אֶחָיו מַה־בֶּצַע כִּי נַהֲרֹג אֶת־אָחִינוּ וְכִסִּינוּ אֶת־דָּמוֹ׃
לְכוּ וְנִמְכְּרֶנּוּ לַיִּשְׁמְעֵאלִים וְיָדֵנוּ אַל־תְּהִי־בוֹ כִּי־אָחִינוּ בְשָׂרֵנוּ הוּא וַיִּשְׁמְעוּ אֶחָיו׃
וַיַּעַבְרוּ אֲנָשִׁים מִדְיָנִים סֹחֲרִים וַיִּמְשְׁכוּ וַיַּעֲלוּ אֶת־יוֹסֵף מִן־הַבּוֹר וַיִּמְכְּרוּ אֶת־יוֹסֵף לַיִּשְׁמְעֵאלִים בְּעֶשְׂרִים כָּסֶף וַיָּבִיאוּ אֶת־יוֹסֵף מִצְרָיְמָה׃
וַיָּשָׁב רְאוּבֵן אֶל־הַבּוֹר וְהִנֵּה אֵין־יוֹסֵף בַּבּוֹר וַיִּקְרַע אֶת־בְּגָדָיו׃
וַיָּשָׁב אֶל־אֶחָיו וַיֹּאמַר הַיֶּלֶד אֵינֶנּוּ וַאֲנִי אָנָה אֲנִי־בָא׃
וַיִּקְחוּ אֶת־כְּתֹנֶת יוֹסֵף וַיִּשְׁחֲטוּ שְׂעִיר עִזִּים וַיִּטְבְּלוּ אֶת־הַכֻּתֹּנֶת בַּדָּם׃
וַיְשַׁלְּחוּ אֶת־כְּתֹנֶת הַפַּסִּים וַיָּבִיאוּ אֶל־אֲבִיהֶם וַיֹּאמְרוּ זֹאת מָצָאנוּ הַכֶּר־נָא הַכְּתֹנֶת בִּנְךָ הִוא אִם־לֹא׃
וַיַּכִּירָהּ וַיֹּאמֶר כְּתֹנֶת בְּנִי חַיָּה רָעָה אֲכָלָתְהוּ טָרֹף טֹרַף יוֹסֵף׃
וַיִּקְרַע יַעֲקֹב שִׂמְלֹתָיו וַיָּשֶׂם שַׂק בְּמָתְנָיו וַיִּתְאַבֵּל עַל־בְּנוֹ יָמִים רַבִּים׃
וַיָּקֻמוּ כָל־בָּנָיו וְכָל־בְּנֹתָיו לְנַחֲמוֹ וַיְמָאֵן לְהִתְנַחֵם וַיֹּאמֶר כִּי־אֵרֵד אֶל־בְּנִי אָבֵל שְׁאֹלָה וַיֵּבְךְּ אֹתוֹ אָבִיו׃
וְהַמְּדָנִים מָכְרוּ אֹתוֹ אֶל־מִצְרָיִם לְפוֹטִיפַר סְרִיס פַּרְעֹה שַׂר הַטַּבָּחִים׃

Chapter 38

וַיְהִי בָּעֵת הַהִוא וַיֵּרֶד יְהוּדָה מֵאֵת אֶחָיו וַיֵּט עַד־אִישׁ עֲדֻלָּמִי וּשְׁמוֹ חִירָה׃
וַיַּרְא־שָׁם יְהוּדָה בַּת־אִישׁ כְּנַעֲנִי וּשְׁמוֹ שׁוּעַ וַיִּקָּחֶהָ וַיָּבֹא אֵלֶיהָ׃
וַתַּהַר וַתֵּלֶד בֵּן וַיִּקְרָא אֶת־שְׁמוֹ עֵר׃
וַתַּהַר עוֹד וַתֵּלֶד בֵּן וַתִּקְרָא אֶת־שְׁמוֹ אוֹנָן׃
וַתֹּסֶף עוֹד וַתֵּלֶד בֵּן וַתִּקְרָא אֶת־שְׁמוֹ שֵׁלָה וְהָיָה בִכְזִיב בְּלִדְתָּהּ אֹתוֹ׃
וַיִּקַּח יְהוּדָה אִשָּׁה לְעֵר בְּכוֹרוֹ וּשְׁמָהּ תָּמָר׃
וַיְהִי עֵר בְּכוֹר יְהוּדָה רַע בְּעֵינֵי יְהוָה וַיְמִתֵהוּ יְהוָה׃
וַיֹּאמֶר יְהוּדָה לְאוֹנָן בֹּא אֶל־אֵשֶׁת אָחִיךָ וְיַבֵּם אֹתָהּ וְהָקֵם זֶרַע לְאָחִיךָ׃
וַיֵּדַע אוֹנָן כִּי לֹּא לוֹ יִהְיֶה הַזָּרַע וְהָיָה אִם־בָּא אֶל־אֵשֶׁת אָחִיו וְשִׁחֵת אַרְצָה לְבִלְתִּי נְתָן־זֶרַע לְאָחִיו׃
וַיֵּרַע בְּעֵינֵי יְהוָה אֲשֶׁר עָשָׂה וַיָּמֶת גַּם־אֹתוֹ׃
וַיֹּאמֶר יְהוּדָה לְתָמָר כַּלָּתוֹ שְׁבִי אַלְמָנָה בֵית־אָבִיךְ עַד־יִגְדַּל שֵׁלָה בְנִי כִּי אָמַר פֶּן־יָמוּת גַּם־הוּא כְּאֶחָיו וַתֵּלֶךְ תָּמָר וַתֵּשֶׁב בֵּית אָבִיהָ׃
וַיִּרְבּוּ הַיָּמִים וַתָּמָת בַּת־שׁוּעַ אֵשֶׁת־יְהוּדָה וַיִּנָּחֶם יְהוּדָה וַיַּעַל עַל־גֹּזֲזֵי צֹאנוֹ הוּא וְחִירָה רֵעֵהוּ הָעֲדֻלָּמִי תִּמְנָתָה׃
וַיֻּגַּד לְתָמָר לֵאמֹר הִנֵּה חָמִיךְ עֹלֶה תִמְנָתָה לָגֹז צֹאנוֹ׃
וַתָּסַר בִּגְדֵי אַלְמְנוּתָהּ מֵעָלֶיהָ וַתְּכַס בַּצָּעִיף וַתִּתְעַלָּף וַתֵּשֶׁב בְּפֶתַח עֵינַיִם אֲשֶׁר עַל־דֶּרֶךְ תִּמְנָתָה כִּי רָאֲתָה כִּי־גָדַל שֵׁלָה וְהִוא לֹא־נִתְּנָה לוֹ לְאִשָּׁה׃
וַיִּרְאֶהָ יְהוּדָה וַיַּחְשְׁבֶהָ לְזוֹנָה כִּי כִסְּתָה פָּנֶיהָ׃
וַיֵּט אֵלֶיהָ אֶל־הַדֶּרֶךְ וַיֹּאמֶר הָבָה־נָּא אָבוֹא אֵלַיִךְ כִּי לֹא יָדַע כִּי כַלָּתוֹ הִוא וַתֹּאמֶר מַה־תִּתֶּן־לִּי כִּי תָבוֹא אֵלָי׃
וַיֹּאמֶר אָנֹכִי אֲשַׁלַּח גְּדִי־עִזִּים מִן־הַצֹּאן וַתֹּאמֶר אִם־תִּתֵּן עֵרָבוֹן עַד שָׁלְחֶךָ׃
וַיֹּאמֶר מָה הָעֵרָבוֹן אֲשֶׁר אֶתֶּן־לָּךְ וַתֹּאמֶר חֹתָמְךָ וּפְתִילֶךָ וּמַטְּךָ אֲשֶׁר בְּיָדֶךָ וַיִּתֶּן־לָּהּ וַיָּבֹא אֵלֶיהָ וַתַּהַר לוֹ׃
וַתָּקָם וַתֵּלֶךְ וַתָּסַר צְעִיפָהּ מֵעָלֶיהָ וַתִּלְבַּשׁ בִּגְדֵי אַלְמְנוּתָהּ׃
וַיִּשְׁלַח יְהוּדָה אֶת־גְּדִי הָעִזִּים בְּיַד רֵעֵהוּ הָעֲדֻלָּמִי לָקַחַת הָעֵרָבוֹן מִיַּד הָאִשָּׁה וְלֹא מְצָאָהּ׃
וַיִּשְׁאַל אֶת־אַנְשֵׁי מְקֹמָהּ לֵאמֹר אַיֵּה הַקְּדֵשָׁה הִוא בָעֵינַיִם עַל־הַדָּרֶךְ וַיֹּאמְרוּ לֹא־הָיְתָה בָזֶה קְדֵשָׁה׃
וַיָּשָׁב אֶל־יְהוּדָה וַיֹּאמֶר לֹא מְצָאתִיהָ וְגַם אַנְשֵׁי הַמָּקוֹם אָמְרוּ לֹא־הָיְתָה בָזֶה קְדֵשָׁה׃
וַיֹּאמֶר יְהוּדָה תִּקַּח־לָהּ פֶּן נִהְיֶה לָבוּז הִנֵּה שָׁלַחְתִּי הַגְּדִי הַזֶּה וְאַתָּה לֹא מְצָאתָהּ׃
וַיְהִי כְּמִשְׁלֹשׁ חֳדָשִׁים וַיֻּגַּד לִיהוּדָה לֵאמֹר זָנְתָה תָּמָר כַּלָּתֶךָ וְגַם הִנֵּה הָרָה לִזְנוּנִים וַיֹּאמֶר יְהוּדָה הוֹצִיאוּהָ וְתִשָּׂרֵף׃
הִוא מוּצֵאת וְהִיא שָׁלְחָה אֶל־חָמִיהָ לֵאמֹר לְאִישׁ אֲשֶׁר־אֵלֶּה לּוֹ אָנֹכִי הָרָה וַתֹּאמֶר הַכֶּר־נָא לְמִי הַחֹתֶמֶת וְהַפְּתִילִים וְהַמַּטֶּה הָאֵלֶּה׃
וַיַּכֵּר יְהוּדָה וַיֹּאמֶר צָדְקָה מִמֶּנִּי כִּי־עַל־כֵּן לֹא־נְתַתִּיהָ לְשֵׁלָה בְנִי וְלֹא־יָסַף עוֹד לְדַעְתָּה׃
וַיְהִי בְּעֵת לִדְתָּהּ וְהִנֵּה תְאוֹמִים בְּבִטְנָהּ׃
וַיְהִי בְלִדְתָּהּ וַיִּתֶּן־יָד וַתִּקַּח הַמְיַלֶּדֶת וַתִּקְשֹׁר עַל־יָדוֹ שָׁנִי לֵאמֹר זֶה יָצָא רִאשֹׁנָה׃
וַיְהִי כְּמֵשִׁיב יָדוֹ וְהִנֵּה יָצָא אָחִיו וַתֹּאמֶר מַה־פָּרַצְתָּ עָלֶיךָ פָּרֶץ וַיִּקְרָא שְׁמוֹ פָּרֶץ׃
וְאַחַר יָצָא אָחִיו אֲשֶׁר עַל־יָדוֹ הַשָּׁנִי וַיִּקְרָא שְׁמוֹ זָרַח׃

Chapter 39

וְיוֹסֵף הוּרַד מִצְרָיְמָה וַיִּקְנֵהוּ פּוֹטִיפַר סְרִיס פַּרְעֹה שַׂר הַטַּבָּחִים אִישׁ מִצְרִי מִיַּד הַיִּשְׁמְעֵאלִים אֲשֶׁר הוֹרִדֻהוּ שָׁמָּה׃
וַיְהִי יְהוָה אֶת־יוֹסֵף וַיְהִי אִישׁ מַצְלִיחַ וַיְהִי בְּבֵית אֲדֹנָיו הַמִּצְרִי׃
וַיַּרְא אֲדֹנָיו כִּי יְהוָה אִתּוֹ וְכֹל אֲשֶׁר־הוּא עֹשֶׂה יְהוָה מַצְלִיחַ בְּיָדוֹ׃
וַיִּמְצָא יוֹסֵף חֵן בְּעֵינָיו וַיְשָׁרֶת אֹתוֹ וַיַּפְקִדֵהוּ עַל־בֵּיתוֹ וְכָל־יֶשׁ־לוֹ נָתַן בְּיָדוֹ׃
וַיְהִי מֵאָז הִפְקִיד אֹתוֹ בְּבֵיתוֹ וְעַל כָּל־אֲשֶׁר יֶשׁ־לוֹ וַיְבָרֶךְ יְהוָה אֶת־בֵּית הַמִּצְרִי בִּגְלַל יוֹסֵף וַיְהִי בִּרְכַּת יְהוָה בְּכָל־אֲשֶׁר יֶשׁ־לוֹ בַּבַּיִת וּבַשָּׂדֶה׃
וַיַּעֲזֹב כָּל־אֲשֶׁר־לוֹ בְּיַד־יוֹסֵף וְלֹא־יָדַע אִתּוֹ מְאוּמָה כִּי אִם־הַלֶּחֶם אֲשֶׁר־הוּא אוֹכֵל וַיְהִי יוֹסֵף יְפֵה־תֹאַר וִיפֵה מַרְאֶה׃
וַיְהִי אַחַר הַדְּבָרִים הָאֵלֶּה וַתִּשָּׂא אֵשֶׁת־אֲדֹנָיו אֶת־עֵינֶיהָ אֶל־יוֹסֵף וַתֹּאמֶר שִׁכְבָה עִמִּי׃
וַיְמָאֵן וַיֹּאמֶר אֶל־אֵשֶׁת אֲדֹנָיו הֵן אֲדֹנִי לֹא־יָדַע אִתִּי מַה־בַּבָּיִת וְכֹל אֲשֶׁר־יֶשׁ־לוֹ נָתַן בְּיָדִי׃
אֵינֶנּוּ גָדוֹל בַּבַּיִת הַזֶּה מִמֶּנִּי וְלֹא־חָשַׂךְ מִמֶּנִּי מְאוּמָה כִּי אִם־אוֹתָךְ בַּאֲשֶׁר אַתְּ־אִשְׁתּוֹ וְאֵיךְ אֶעֱשֶׂה הָרָעָה הַגְּדֹלָה הַזֹּאת וְחָטָאתִי לֵאלֹהִים׃
וַיְהִי כְּדַבְּרָהּ אֶל־יוֹסֵף יוֹם יוֹם וְלֹא־שָׁמַע אֵלֶיהָ לִשְׁכַּב אֶצְלָהּ לִהְיוֹת עִמָּהּ׃
וַיְהִי כְּהַיּוֹם הַזֶּה וַיָּבֹא הַבַּיְתָה לַעֲשׂוֹת מְלַאכְתּוֹ וְאֵין אִישׁ מֵאַנְשֵׁי הַבַּיִת שָׁם בַּבָּיִת׃
וַתִּתְפְּשֵׂהוּ בְּבִגְדוֹ לֵאמֹר שִׁכְבָה עִמִּי וַיַּעֲזֹב בִּגְדוֹ בְּיָדָהּ וַיָּנָס וַיֵּצֵא הַחוּצָה׃
וַיְהִי כִּרְאוֹתָהּ כִּי־עָזַב בִּגְדוֹ בְּיָדָהּ וַיָּנָס הַחוּצָה׃
וַתִּקְרָא לְאַנְשֵׁי בֵיתָהּ וַתֹּאמֶר לָהֶם לֵאמֹר רְאוּ הֵבִיא לָנוּ אִישׁ עִבְרִי לְצַחֶק בָּנוּ בָּא אֵלַי לִשְׁכַּב עִמִּי וָאֶקְרָא בְּקוֹל גָּדוֹל׃
וַיְהִי כְשָׁמְעוֹ כִּי־הֲרִימֹתִי קוֹלִי וָאֶקְרָא וַיַּעֲזֹב בִּגְדוֹ אֶצְלִי וַיָּנָס וַיֵּצֵא הַחוּצָה׃
וַתַּנַּח בִּגְדוֹ אֶצְלָהּ עַד־בּוֹא אֲדֹנָיו אֶל־בֵּיתוֹ׃
וַתְּדַבֵּר אֵלָיו כַּדְּבָרִים הָאֵלֶּה לֵאמֹר בָּא־אֵלַי הָעֶבֶד הָעִבְרִי אֲשֶׁר־הֵבֵאתָ לָּנוּ לְצַחֶק בִּי׃
וַיְהִי כַּהֲרִימִי קוֹלִי וָאֶקְרָא וַיַּעֲזֹב בִּגְדוֹ אֶצְלִי וַיָּנָס הַחוּצָה׃
וַיְהִי כִשְׁמֹעַ אֲדֹנָיו אֶת־דִּבְרֵי אִשְׁתּוֹ אֲשֶׁר דִּבְּרָה אֵלָיו לֵאמֹר כַּדְּבָרִים הָאֵלֶּה עָשָׂהּ לִי עַבְדֶּךָ וַיִּחַר אַפּוֹ׃
וַיִּקַּח אֲדֹנֵי יוֹסֵף אֹתוֹ וַיִּתְּנֵהוּ אֶל־בֵּית הַסֹּהַר מְקוֹם אֲשֶׁר־אסורי [אֲסִירֵי] הַמֶּלֶךְ אֲסוּרִים וַיְהִי־שָׁם בְּבֵית הַסֹּהַר׃
וַיְהִי יְהוָה אֶת־יוֹסֵף וַיֵּט אֵלָיו חָסֶד וַיִּתֵּן חִנּוֹ בְּעֵינֵי שַׂר בֵּית־הַסֹּהַר׃
וַיִּתֵּן שַׂר בֵּית־הַסֹּהַר בְּיַד־יוֹסֵף אֵת כָּל־הָאֲסִירִם אֲשֶׁר בְּבֵית הַסֹּהַר וְאֵת כָּל־אֲשֶׁר עֹשִׂים שָׁם הוּא הָיָה עֹשֶׂה׃
אֵין שַׂר בֵּית־הַסֹּהַר רֹאֶה אֶת־כָּל־מְאוּמָה בְּיָדוֹ בַּאֲשֶׁר יְהוָה אִתּוֹ וַאֲשֶׁר־הוּא עֹשֶׂה יְהוָה מַצְלִיחַ׃

Chapter 40

וַיְהִי אַחַר הַדְּבָרִים הָאֵלֶּה חָטְאוּ מַשְׁקֵה מֶלֶךְ־מִצְרַיִם וְהָאֹפֶה לַאֲדֹנֵיהֶם לְמֶלֶךְ מִצְרָיִם׃
וַיִּקְצֹף פַּרְעֹה עַל שְׁנֵי סָרִיסָיו עַל שַׂר הַמַּשְׁקִים וְעַל שַׂר הָאוֹפִים׃
וַיִּתֵּן אֹתָם בְּמִשְׁמַר בֵּית שַׂר הַטַבָּחִים אֶל־בֵּית הַסֹּהַר מְקוֹם אֲשֶׁר יוֹסֵף אָסוּר שָׁם׃
וַיִּפְקֹד שַׂר הַטַּבָּחִים אֶת־יוֹסֵף אִתָּם וַיְשָׁרֶת אֹתָם וַיִּהְיוּ יָמִים בְּמִשְׁמָר׃
וַיַּחַלְמוּ חֲלוֹם שְׁנֵיהֶם אִישׁ חֲלֹמוֹ בְּלַיְלָה אֶחָד אִישׁ כְּפִתְרוֹן חֲלֹמוֹ הַמַּשְׁקֶה וְהָאֹפֶה אֲשֶׁר לְמֶלֶךְ מִצְרַיִם אֲשֶׁר אֲסוּרִים בְּבֵית הַסֹּהַר׃
וַיָּבֹא אֲלֵיהֶם יוֹסֵף בַּבֹּקֶר וַיַּרְא אֹתָם וְהִנָּם זֹעֲפִים׃
וַיִּשְׁאַל אֶת־סְרִיסֵי פַרְעֹה אֲשֶׁר אִתּוֹ בְמִשְׁמַר בֵּית אֲדֹנָיו לֵאמֹר מַדּוּעַ פְּנֵיכֶם רָעִים הַיּוֹם׃
וַיֹּאמְרוּ אֵלָיו חֲלוֹם חָלַמְנוּ וּפֹתֵר אֵין אֹתוֹ וַיֹּאמֶר אֲלֵהֶם יוֹסֵף הֲלוֹא לֵאלֹהִים פִּתְרֹנִים סַפְּרוּ־נָא לִי׃
וַיְסַפֵּר שַׂר־הַמַּשְׁקִים אֶת־חֲלֹמוֹ לְיוֹסֵף וַיֹּאמֶר לוֹ בַּחֲלוֹמִי וְהִנֵּה־גֶפֶן לְפָנָי׃
וּבַגֶּפֶן שְׁלֹשָׁה שָׂרִיגִם וְהִיא כְפֹרַחַת עָלְתָה נִצָּהּ הִבְשִׁילוּ אַשְׁכְּלֹתֶיהָ עֲנָבִים׃
וְכוֹס פַּרְעֹה בְּיָדִי וָאֶקַּח אֶת־הָעֲנָבִים וָאֶשְׂחַט אֹתָם אֶל־כּוֹס פַּרְעֹה וָאֶתֵּן אֶת־הַכּוֹס עַל־כַּף פַּרְעֹה׃
וַיֹּאמֶר לוֹ יוֹסֵף זֶה פִּתְרֹנוֹ שְׁלֹשֶׁת הַשָּׂרִגִים שְׁלֹשֶׁת יָמִים הֵם׃
בְּעוֹד שְׁלֹשֶׁת יָמִים יִשָּׂא פַרְעֹה אֶת־רֹאשֶׁךָ וַהֲשִׁיבְךָ עַל־כַּנֶּךָ וְנָתַתָּ כוֹס־פַּרְעֹה בְּיָדוֹ כַּמִּשְׁפָּט הָרִאשׁוֹן אֲשֶׁר הָיִיתָ מַשְׁקֵהוּ׃
כִּי אִם־זְכַרְתַּנִי אִתְּךָ כַּאֲשֶׁר יִיטַב לָךְ וְעָשִׂיתָ־נָּא עִמָּדִי חָסֶד וְהִזְכַּרְתַּנִי אֶל־פַּרְעֹה וְהוֹצֵאתַנִי מִן־הַבַּיִת הַזֶּה׃
כִּי־גֻנֹּב גֻּנַּבְתִּי מֵאֶרֶץ הָעִבְרִים וְגַם־פֹּה לֹא־עָשִׂיתִי מְאוּמָה כִּי־שָׂמוּ אֹתִי בַּבּוֹר׃
וַיַּרְא שַׂר־הָאֹפִים כִּי טוֹב פָּתָר וַיֹּאמֶר אֶל־יוֹסֵף אַף־אֲנִי בַּחֲלוֹמִי וְהִנֵּה שְׁלֹשָׁה סַלֵּי חֹרִי עַל־רֹאשִׁי׃
וּבַסַּל הָעֶלְיוֹן מִכֹּל מַאֲכַל פַּרְעֹה מַעֲשֵׂה אֹפֶה וְהָעוֹף אֹכֵל אֹתָם מִן־הַסַּל מֵעַל רֹאשִׁי׃
וַיַּעַן יוֹסֵף וַיֹּאמֶר זֶה פִּתְרֹנוֹ שְׁלֹשֶׁת הַסַּלִּים שְׁלֹשֶׁת יָמִים הֵם׃
בְּעוֹד שְׁלֹשֶׁת יָמִים יִשָּׂא פַרְעֹה אֶת־רֹאשְׁךָ מֵעָלֶיךָ וְתָלָה אוֹתְךָ עַל־עֵץ וְאָכַל הָעוֹף אֶת־בְּשָׂרְךָ מֵעָלֶיךָ׃
וַיְהִי בַּיּוֹם הַשְּׁלִישִׁי יוֹם הֻלֶּדֶת אֶת־פַּרְעֹה וַיַּעַשׂ מִשְׁתֶּה לְכָל־עֲבָדָיו וַיִּשָּׂא אֶת־רֹאשׁ שַׂר הַמַּשְׁקִים וְאֶת־רֹאשׁ שַׂר הָאֹפִים בְּתוֹךְ עֲבָדָיו׃
וַיָּשֶׁב אֶת־שַׂר הַמַּשְׁקִים עַל־מַשְׁקֵהוּ וַיִּתֵּן הַכּוֹס עַל־כַּף פַּרְעֹה׃
וְאֵת שַׂר הָאֹפִים תָּלָה כַּאֲשֶׁר פָּתַר לָהֶם יוֹסֵף׃
וְלֹא־זָכַר שַׂר־הַמַּשְׁקִים אֶת־יוֹסֵף וַיִּשְׁכָּחֵהוּ׃

Chapter 41

וַיְהִי מִקֵּץ שְׁנָתַיִם יָמִים וּפַרְעֹה חֹלֵם וְהִנֵּה עֹמֵד עַל־הַיְאֹר׃
וְהִנֵּה מִן־הַיְאֹר עֹלֹת שֶׁבַע פָּרוֹת יְפוֹת מַרְאֶה וּבְרִיאֹת בָּשָׂר וַתִּרְעֶינָה בָּאָחוּ׃
וְהִנֵּה שֶׁבַע פָּרוֹת אֲחֵרוֹת עֹלוֹת אַחֲרֵיהֶן מִן־הַיְאֹר רָעוֹת מַרְאֶה וְדַקּוֹת בָּשָׂר וַתַּעֲמֹדְנָה אֵצֶל הַפָּרוֹת עַל־שְׂפַת הַיְאֹר׃
וַתֹּאכַלְנָה הַפָּרוֹת רָעוֹת הַמַּרְאֶה וְדַקֹּת הַבָּשָׂר אֵת שֶׁבַע הַפָּרוֹת יְפֹת הַמַּרְאֶה וְהַבְּרִיאֹת וַיִּיקַץ פַּרְעֹה׃
וַיִּישָׁן וַיַּחֲלֹם שֵׁנִית וְהִנֵּה שֶׁבַע שִׁבֳּלִים עֹלוֹת בְּקָנֶה אֶחָד בְּרִיאוֹת וְטֹבוֹת׃
וְהִנֵּה שֶׁבַע שִׁבֳּלִים דַּקּוֹת וּשְׁדוּפֹת קָדִים צֹמְחוֹת אַחֲרֵיהֶן׃
וַתִּבְלַעְנָה הַשִּׁבֳּלִים הַדַּקּוֹת אֵת שֶׁבַע הַשִּׁבֳּלִים הַבְּרִיאוֹת וְהַמְּלֵאוֹת וַיִּיקַץ פַּרְעֹה וְהִנֵּה חֲלוֹם׃
וַיְהִי בַבֹּקֶר וַתִּפָּעֶם רוּחוֹ וַיִּשְׁלַח וַיִּקְרָא אֶת־כָּל־חַרְטֻמֵּי מִצְרַיִם וְאֶת־כָּל־חֲכָמֶיהָ וַיְסַפֵּר פַּרְעֹה לָהֶם אֶת־חֲלֹמוֹ וְאֵין־פּוֹתֵר אוֹתָם לְפַרְעֹה׃
וַיְדַבֵּר שַׂר הַמַּשְׁקִים אֶת־פַּרְעֹה לֵאמֹר אֶת־חֲטָאַי אֲנִי מַזְכִּיר הַיּוֹם׃
פַּרְעֹה קָצַף עַל־עֲבָדָיו וַיִּתֵּן אֹתִי בְּמִשְׁמַר בֵּית שַׂר הַטַּבָּחִים אֹתִי וְאֵת שַׂר הָאֹפִים׃
וַנַּחַלְמָה חֲלוֹם בְּלַיְלָה אֶחָד אֲנִי וָהוּא אִישׁ כְּפִתְרוֹן חֲלֹמוֹ חָלָמְנוּ׃
וְשָׁם אִתָּנוּ נַעַר עִבְרִי עֶבֶד לְשַׂר הַטַּבָּחִים וַנְּסַפֶּר־לוֹ וַיִּפְתָּר־לָנוּ אֶת־חֲלֹמֹתֵינוּ אִישׁ כַּחֲלֹמוֹ פָּתָר׃
וַיְהִי כַּאֲשֶׁר פָּתַר־לָנוּ כֵּן הָיָה אֹתִי הֵשִׁיב עַל־כַּנִּי וְאֹתוֹ תָלָה׃
וַיִּשְׁלַח פַּרְעֹה וַיִּקְרָא אֶת־יוֹסֵף וַיְרִיצֻהוּ מִן־הַבּוֹר וַיְגַלַּח וַיְחַלֵּף שִׂמְלֹתָיו וַיָּבֹא אֶל־פַּרְעֹה׃
וַיֹּאמֶר פַּרְעֹה אֶל־יוֹסֵף חֲלוֹם חָלַמְתִּי וּפֹתֵר אֵין אֹתוֹ וַאֲנִי שָׁמַעְתִּי עָלֶיךָ לֵאמֹר תִּשְׁמַע חֲלוֹם לִפְתֹּר אֹתוֹ׃
וַיַּעַן יוֹסֵף אֶת־פַּרְעֹה לֵאמֹר בִּלְעָדָי אֱלֹהִים יַעֲנֶה אֶת־שְׁלוֹם פַּרְעֹה׃
וַיְדַבֵּר פַּרְעֹה אֶל־יוֹסֵף בַּחֲלֹמִי הִנְנִי עֹמֵד עַל־שְׂפַת הַיְאֹר׃
וְהִנֵּה מִן־הַיְאֹר עֹלֹת שֶׁבַע פָּרוֹת בְּרִיאוֹת בָּשָׂר וִיפֹת תֹּאַר וַתִּרְעֶינָה בָּאָחוּ׃
וְהִנֵּה שֶׁבַע־פָּרוֹת אֲחֵרוֹת עֹלוֹת אַחֲרֵיהֶן דַּלּוֹת וְרָעוֹת תֹּאַר מְאֹד וְרַקּוֹת בָּשָׂר לֹא־רָאִיתִי כָהֵנָּה בְּכָל־אֶרֶץ מִצְרַיִם לָרֹעַ׃
וַתֹּאכַלְנָה הַפָּרוֹת הָרַקּוֹת וְהָרָעוֹת אֵת שֶׁבַע הַפָּרוֹת הָרִאשֹׁנוֹת הַבְּרִיאֹת׃
וַתָּבֹאנָה אֶל־קִרְבֶּנָה וְלֹא נוֹדַע כִּי־בָאוּ אֶל־קִרְבֶּנָה וּמַרְאֵיהֶן רַע כַּאֲשֶׁר בַּתְּחִלָּה וָאִיקָץ׃
וָאֵרֶא בַּחֲלֹמִי וְהִנֵּה שֶׁבַע שִׁבֳּלִים עֹלֹת בְּקָנֶה אֶחָד מְלֵאֹת וְטֹבוֹת׃
וְהִנֵּה שֶׁבַע שִׁבֳּלִים צְנֻמוֹת דַּקּוֹת שְׁדֻפוֹת קָדִים צֹמְחוֹת אַחֲרֵיהֶם׃
וַתִּבְלַעְןָ הָשִׁבֳּלִים הַדַּקֹּת אֵת שֶׁבַע הַשִׁבֳּלִים הַטֹּבוֹת וָאֹמַר אֶל־הַחַרְטֻמִּים וְאֵין מַגִּיד לִי׃
וַיֹּאמֶר יוֹסֵף אֶל־פַּרְעֹה חֲלוֹם פַּרְעֹה אֶחָד הוּא אֵת אֲשֶׁר הָאֱלֹהִים עֹשֶׂה הִגִּיד לְפַרְעֹה׃
שֶׁבַע פָּרֹת הַטֹּבֹת שֶׁבַע שָׁנִים הֵנָּה וְשֶׁבַע הַשִּׁבֳּלִים הַטֹּבֹת שֶׁבַע שָׁנִים הֵנָּה חֲלוֹם אֶחָד הוּא׃
וְשֶׁבַע הַפָּרוֹת הָרַקּוֹת וְהָרָעֹת הָעֹלֹת אַחֲרֵיהֶן שֶׁבַע שָׁנִים הֵנָּה וְשֶׁבַע הַשִׁבֳּלִים הָרֵקוֹת שְׁדֻפוֹת הַקָּדִים יִהְיוּ שֶׁבַע שְׁנֵי רָעָב׃
הוּא הַדָּבָר אֲשֶׁר דִּבַּרְתִּי אֶל־פַּרְעֹה אֲשֶׁר הָאֱלֹהִים עֹשֶׂה הֶרְאָה אֶת־פַּרְעֹה׃
הִנֵּה שֶׁבַע שָׁנִים בָּאוֹת שָׂבָע גָּדוֹל בְּכָל־אֶרֶץ מִצְרָיִם׃
וְקָמוּ שֶׁבַע שְׁנֵי רָעָב אַחֲרֵיהֶן וְנִשְׁכַּח כָּל־הַשָּׂבָע בְּאֶרֶץ מִצְרָיִם וְכִלָּה הָרָעָב אֶת־הָאָרֶץ׃
וְלֹא־יִוָּדַע הַשָּׂבָע בָּאָרֶץ מִפְּנֵי הָרָעָב הַהוּא אַחֲרֵי־כֵן כִּי־כָבֵד הוּא מְאֹד׃
וְעַל הִשָּׁנוֹת הַחֲלוֹם אֶל־פַּרְעֹה פַּעֲמָיִם כִּי־נָכוֹן הַדָּבָר מֵעִם הָאֱלֹהִים וּמְמַהֵר הָאֱלֹהִים לַעֲשֹׂתוֹ׃
וְעַתָּה יֵרֶא פַרְעֹה אִישׁ נָבוֹן וְחָכָם וִישִׁיתֵהוּ עַל־אֶרֶץ מִצְרָיִם׃
יַעֲשֶׂה פַרְעֹה וְיַפְקֵד פְּקִדִים עַל־הָאָרֶץ וְחִמֵּשׁ אֶת־אֶרֶץ מִצְרַיִם בְּשֶׁבַע שְׁנֵי הַשָּׂבָע׃
וְיִקְבְּצוּ אֶת־כָּל־אֹכֶל הַשָּׁנִים הַטֹּבֹת הַבָּאֹת הָאֵלֶּה וְיִצְבְּרוּ־בָר תַּחַת יַד־פַּרְעֹה אֹכֶל בֶּעָרִים וְשָׁמָרוּ׃
וְהָיָה הָאֹכֶל לְפִקָּדוֹן לָאָרֶץ לְשֶׁבַע שְׁנֵי הָרָעָב אֲשֶׁר תִּהְיֶיןָ בְּאֶרֶץ מִצְרָיִם וְלֹא־תִכָּרֵת הָאָרֶץ בָּרָעָב׃
וַיִּיטַב הַדָּבָר בְּעֵינֵי פַרְעֹה וּבְעֵינֵי כָּל־עֲבָדָיו׃
וַיֹּאמֶר פַּרְעֹה אֶל־עֲבָדָיו הֲנִמְצָא כָזֶה אִישׁ אֲשֶׁר רוּחַ אֱלֹהִים בּוֹ׃
וַיֹּאמֶר פַּרְעֹה אֶל־יוֹסֵף אַחֲרֵי הוֹדִיעַ אֱלֹהִים אוֹתְךָ אֶת־כָּל־זֹאת אֵין־נָבוֹן וְחָכָם כָּמוֹךָ׃
אַתָּה תִּהְיֶה עַל־בֵּיתִי וְעַל־פִּיךָ יִשַּׁק כָּל־עַמִּי רַק הַכִּסֵּא אֶגְדַּל מִמֶּךָּ׃
וַיֹּאמֶר פַּרְעֹה אֶל־יוֹסֵף רְאֵה נָתַתִּי אֹתְךָ עַל כָּל־אֶרֶץ מִצְרָיִם׃
וַיָּסַר פַּרְעֹה אֶת־טַבַּעְתּוֹ מֵעַל יָדוֹ וַיִּתֵּן אֹתָהּ עַל־יַד יוֹסֵף וַיַּלְבֵּשׁ אֹתוֹ בִּגְדֵי־שֵׁשׁ וַיָּשֶׂם רְבִד הַזָּהָב עַל־צַוָּארוֹ׃
וַיַּרְכֵּב אֹתוֹ בְּמִרְכֶּבֶת הַמִּשְׁנֶה אֲשֶׁר־לוֹ וַיִּקְרְאוּ לְפָנָיו אַבְרֵךְ וְנָתוֹן אֹתוֹ עַל כָּל־אֶרֶץ מִצְרָיִם׃
וַיֹּאמֶר פַּרְעֹה אֶל־יוֹסֵף אֲנִי פַרְעֹה וּבִלְעָדֶיךָ לֹא־יָרִים אִישׁ אֶת־יָדוֹ וְאֶת־רַגְלוֹ בְּכָל־אֶרֶץ מִצְרָיִם׃
וַיִּקְרָא פַרְעֹה שֵׁם־יוֹסֵף צָפְנַת פַּעְנֵחַ וַיִּתֶּן־לוֹ אֶת־אָסְנַת בַּת־פּוֹטִי פֶרַע כֹּהֵן אֹן לְאִשָּׁה וַיֵּצֵא יוֹסֵף עַל־אֶרֶץ מִצְרָיִם׃
וְיוֹסֵף בֶּן־שְׁלֹשִׁים שָׁנָה בְּעָמְדוֹ לִפְנֵי פַּרְעֹה מֶלֶךְ־מִצְרָיִם וַיֵּצֵא יוֹסֵף מִלִּפְנֵי פַרְעֹה וַיַּעְבֹר בְּכָל־אֶרֶץ מִצְרָיִם׃
וַתַּעַשׂ הָאָרֶץ בְּשֶׁבַע שְׁנֵי הַשָּׂבָע לִקְמָצִים׃
וַיִּקְבֹּץ אֶת־כָּל־אֹכֶל שֶׁבַע שָׁנִים אֲשֶׁר הָיוּ בְּאֶרֶץ מִצְרַיִם וַיִּתֶּן־אֹכֶל בֶּעָרִים אֹכֶל שְׂדֵה־הָעִיר אֲשֶׁר סְבִיבֹתֶיהָ נָתַן בְּתוֹכָהּ׃
וַיִּצְבֹּר יוֹסֵף בָּר כְּחוֹל הַיָּם הַרְבֵּה מְאֹד עַד כִּי־חָדַל לִסְפֹּר כִּי־אֵין מִסְפָּר׃
וּלְיוֹסֵף יֻלַּד שְׁנֵי בָנִים בְּטֶרֶם תָּבוֹא שְׁנַת הָרָעָב אֲשֶׁר יָלְדָה־לּוֹ אָסְנַת בַּת־פּוֹטִי פֶרַע כֹּהֵן אוֹן׃
וַיִּקְרָא יוֹסֵף אֶת־שֵׁם הַבְּכוֹר מְנַשֶּׁה כִּי־נַשַּׁנִי אֱלֹהִים אֶת־כָּל־עֲמָלִי וְאֵת כָּל־בֵּית אָבִי׃
וְאֵת שֵׁם הַשֵּׁנִי קָרָא אֶפְרָיִם כִּי־הִפְרַנִי אֱלֹהִים בְּאֶרֶץ עָנְיִי׃
וַתִּכְלֶינָה שֶׁבַע שְׁנֵי הַשָּׂבָע אֲשֶׁר הָיָה בְּאֶרֶץ מִצְרָיִם׃
וַתְּחִלֶּינָה שֶׁבַע שְׁנֵי הָרָעָב לָבוֹא כַּאֲשֶׁר אָמַר יוֹסֵף וַיְהִי רָעָב בְּכָל־הָאֲרָצוֹת וּבְכָל־אֶרֶץ מִצְרַיִם הָיָה לָחֶם׃
וַתִּרְעַב כָּל־אֶרֶץ מִצְרַיִם וַיִּצְעַק הָעָם אֶל־פַּרְעֹה לַלָּחֶם וַיֹּאמֶר פַּרְעֹה לְכָל־מִצְרַיִם לְכוּ אֶל־יוֹסֵף אֲשֶׁר־יֹאמַר לָכֶם תַּעֲשׂוּ׃
וְהָרָעָב הָיָה עַל כָּל־פְּנֵי הָאָרֶץ וַיִּפְתַּח יוֹסֵף אֶת־כָּל־אֲשֶׁר בָּהֶם וַיִּשְׁבֹּר לְמִצְרַיִם וַיֶּחֱזַק הָרָעָב בְּאֶרֶץ מִצְרָיִם׃
וְכָל־הָאָרֶץ בָּאוּ מִצְרַיְמָה לִשְׁבֹּר אֶל־יוֹסֵף כִּי־חָזַק הָרָעָב בְּכָל־הָאָרֶץ׃

Chapter 42

וַיַּרְא יַעֲקֹב כִּי יֶשׁ־שֶׁבֶר בְּמִצְרָיִם וַיֹּאמֶר יַעֲקֹב לְבָנָיו לָמָּה תִּתְרָאוּ׃
וַיֹּאמֶר הִנֵּה שָׁמַעְתִּי כִּי יֶשׁ־שֶׁבֶר בְּמִצְרָיִם רְדוּ־שָׁמָּה וְשִׁבְרוּ־לָנוּ מִשָּׁם וְנִחְיֶה וְלֹא נָמוּת׃
וַיֵּרְדוּ אֲחֵי־יוֹסֵף עֲשָׂרָה לִשְׁבֹּר בָּר מִמִּצְרָיִם׃
וְאֶת־בִּנְיָמִין אֲחִי יוֹסֵף לֹא־שָׁלַח יַעֲקֹב אֶת־אֶחָיו כִּי אָמַר פֶּן־יִקְרָאֶנּוּ אָסוֹן׃
וַיָּבֹאוּ בְּנֵי יִשְׂרָאֵל לִשְׁבֹּר בְּתוֹךְ הַבָּאִים כִּי־הָיָה הָרָעָב בְּאֶרֶץ כְּנָעַן׃
וְיוֹסֵף הוּא הַשַּׁלִּיט עַל־הָאָרֶץ הוּא הַמַּשְׁבִּיר לְכָל־עַם הָאָרֶץ וַיָּבֹאוּ אֲחֵי יוֹסֵף וַיִּשְׁתַּחֲווּ־לוֹ אַפַּיִם אָרְצָה׃
וַיַּרְא יוֹסֵף אֶת־אֶחָיו וַיַּכִּרֵם וַיִּתְנַכֵּר אֲלֵיהֶם וַיְדַבֵּר אִתָּם קָשׁוֹת וַיֹּאמֶר אֲלֵהֶם מֵאַיִן בָּאתֶם וַיֹּאמְרוּ מֵאֶרֶץ כְּנַעַן לִשְׁבָּר־אֹכֶל׃
וַיַּכֵּר יוֹסֵף אֶת־אֶחָיו וְהֵם לֹא הִכִּרֻהוּ׃
וַיִּזְכֹּר יוֹסֵף אֵת הַחֲלֹמוֹת אֲשֶׁר חָלַם לָהֶם וַיֹּאמֶר אֲלֵהֶם מְרַגְּלִים אַתֶּם לִרְאוֹת אֶת־עֶרְוַת הָאָרֶץ בָּאתֶם׃
וַיֹּאמְרוּ אֵלָיו לֹא אֲדֹנִי וַעֲבָדֶיךָ בָּאוּ לִשְׁבָּר־אֹכֶל׃
כֻּלָּנוּ בְּנֵי אִישׁ־אֶחָד נָחְנוּ כֵּנִים אֲנַחְנוּ לֹא־הָיוּ עֲבָדֶיךָ מְרַגְּלִים׃
וַיֹּאמֶר אֲלֵהֶם לֹא כִּי־עֶרְוַת הָאָרֶץ בָּאתֶם לִרְאוֹת׃
וַיֹּאמְרוּ שְׁנֵים עָשָׂר עֲבָדֶיךָ אַחִים אֲנַחְנוּ בְּנֵי אִישׁ־אֶחָד בְּאֶרֶץ כְּנָעַן וְהִנֵּה הַקָּטֹן אֶת־אָבִינוּ הַיּוֹם וְהָאֶחָד אֵינֶנּוּ׃
וַיֹּאמֶר אֲלֵהֶם יוֹסֵף הוּא אֲשֶׁר דִּבַּרְתִּי אֲלֵכֶם לֵאמֹר מְרַגְּלִים אַתֶּם׃
בְּזֹאת תִּבָּחֵנוּ חֵי פַרְעֹה אִם־תֵּצְאוּ מִזֶּה כִּי אִם־בְּבוֹא אֲחִיכֶם הַקָּטֹן הֵנָּה׃
שִׁלְחוּ מִכֶּם אֶחָד וְיִקַּח אֶת־אֲחִיכֶם וְאַתֶּם הֵאָסְרוּ וְיִבָּחֲנוּ דִּבְרֵיכֶם הַאֱמֶת אִתְּכֶם וְאִם־לֹא חֵי פַרְעֹה כִּי מְרַגְּלִים אַתֶּם׃
וַיֶּאֱסֹף אֹתָם אֶל־מִשְׁמָר שְׁלֹשֶׁת יָמִים׃
וַיֹּאמֶר אֲלֵהֶם יוֹסֵף בַּיּוֹם הַשְּׁלִישִׁי זֹאת עֲשׂוּ וִחְיוּ אֶת־הָאֱלֹהִים אֲנִי יָרֵא׃
אִם־כֵּנִים אַתֶּם אֲחִיכֶם אֶחָד יֵאָסֵר בְּבֵית מִשְׁמַרְכֶם וְאַתֶּם לְכוּ הָבִיאוּ שֶׁבֶר רַעֲבוֹן בָּתֵּיכֶם׃
וְאֶת־אֲחִיכֶם הַקָּטֹן תָּבִיאוּ אֵלַי וְיֵאָמְנוּ דִבְרֵיכֶם וְלֹא תָמוּתוּ וַיַּעֲשׂוּ־כֵן׃
וַיֹּאמְרוּ אִישׁ אֶל־אָחִיו אֲבָל אֲשֵׁמִים אֲנַחְנוּ עַל־אָחִינוּ אֲשֶׁר רָאִינוּ צָרַת נַפְשׁוֹ בְּהִתְחַנְנוֹ אֵלֵינוּ וְלֹא שָׁמָעְנוּ עַל־כֵּן בָּאָה אֵלֵינוּ הַצָּרָה הַזֹּאת׃
וַיַּעַן רְאוּבֵן אֹתָם לֵאמֹר הֲלוֹא אָמַרְתִּי אֲלֵיכֶם לֵאמֹר אַל־תֶּחֶטְאוּ בַיֶּלֶד וְלֹא שְׁמַעְתֶּם וְגַם־דָּמוֹ הִנֵּה נִדְרָשׁ׃
וְהֵם לֹא יָדְעוּ כִּי שֹׁמֵעַ יוֹסֵף כִּי הַמֵּלִיץ בֵּינֹתָם׃
וַיִּסֹּב מֵעֲלֵיהֶם וַיֵּבְךְּ וַיָּשָׁב אֲלֵהֶם וַיְדַבֵּר אֲלֵהֶם וַיִּקַּח מֵאִתָּם אֶת־שִׁמְעוֹן וַיֶּאֱסֹר אֹתוֹ לְעֵינֵיהֶם׃
וַיְצַו יוֹסֵף וַיְמַלְאוּ אֶת־כְּלֵיהֶם בָּר וּלְהָשִׁיב כַּסְפֵּיהֶם אִישׁ אֶל־שַׂקּוֹ וְלָתֵת לָהֶם צֵדָה לַדָּרֶךְ וַיַּעַשׂ לָהֶם כֵּן׃
וַיִּשְׂאוּ אֶת־שִׁבְרָם עַל־חֲמֹרֵיהֶם וַיֵּלְכוּ מִשָּׁם׃
וַיִּפְתַּח הָאֶחָד אֶת־שַׂקּוֹ לָתֵת מִסְפּוֹא לַחֲמֹרוֹ בַּמָּלוֹן וַיַּרְא אֶת־כַּסְפּוֹ וְהִנֵּה־הוּא בְּפִי אַמְתַּחְתּוֹ׃
וַיֹּאמֶר אֶל־אֶחָיו הוּשַׁב כַּסְפִּי וְגַם הִנֵּה בְאַמְתַּחְתִּי וַיֵּצֵא לִבָּם וַיֶּחֶרְדוּ אִישׁ אֶל־אָחִיו לֵאמֹר מַה־זֹּאת עָשָׂה אֱלֹהִים לָנוּ׃
וַיָּבֹאוּ אֶל־יַעֲקֹב אֲבִיהֶם אַרְצָה כְּנָעַן וַיַּגִּידוּ לוֹ אֵת כָּל־הַקֹּרֹת אֹתָם לֵאמֹר׃
דִּבֶּר הָאִישׁ אֲדֹנֵי הָאָרֶץ אִתָּנוּ קָשׁוֹת וַיִּתֵּן אֹתָנוּ כִּמְרַגְּלִים אֶת־הָאָרֶץ׃
וַנֹּאמֶר אֵלָיו כֵּנִים אֲנָחְנוּ לֹא הָיִינוּ מְרַגְּלִים׃
שְׁנֵים־עָשָׂר אֲנַחְנוּ אַחִים בְּנֵי אָבִינוּ הָאֶחָד אֵינֶנּוּ וְהַקָּטֹן הַיּוֹם אֶת־אָבִינוּ בְּאֶרֶץ כְּנָעַן׃
וַיֹּאמֶר אֵלֵינוּ הָאִישׁ אֲדֹנֵי הָאָרֶץ בְּזֹאת אֵדַע כִּי כֵנִים אַתֶּם אֲחִיכֶם הָאֶחָד הַנִּיחוּ אִתִּי וְאֶת־רַעֲבוֹן בָּתֵּיכֶם קְחוּ וָלֵכוּ׃
וְהָבִיאוּ אֶת־אֲחִיכֶם הַקָּטֹן אֵלַי וְאֵדְעָה כִּי לֹא מְרַגְּלִים אַתֶּם כִּי כֵנִים אַתֶּם אֶת־אֲחִיכֶם אֶתֵּן לָכֶם וְאֶת־הָאָרֶץ תִּסְחָרוּ׃
וַיְהִי הֵם מְרִיקִים שַׂקֵּיהֶם וְהִנֵּה־אִישׁ צְרוֹר־כַּסְפּוֹ בְּשַׂקּוֹ וַיִּרְאוּ אֶת־צְרֹרוֹת כַּסְפֵּיהֶם הֵמָּה וַאֲבִיהֶם וַיִּירָאוּ׃
וַיֹּאמֶר אֲלֵהֶם יַעֲקֹב אֲבִיהֶם אֹתִי שִׁכַּלְתֶּם יוֹסֵף אֵינֶנּוּ וְשִׁמְעוֹן אֵינֶנּוּ וְאֶת־בִּנְיָמִן תִּקָּחוּ עָלַי הָיוּ כֻלָּנָה׃
וַיֹּאמֶר רְאוּבֵן אֶל־אָבִיו לֵאמֹר אֶת־שְׁנֵי בָנַי תָּמִית אִם־לֹא אֲבִיאֶנּוּ אֵלֶיךָ תְּנָה אֹתוֹ עַל־יָדִי וַאֲנִי אֲשִׁיבֶנּוּ אֵלֶיךָ׃
וַיֹּאמֶר לֹא־יֵרֵד בְּנִי עִמָּכֶם כִּי־אָחִיו מֵת וְהוּא לְבַדּוֹ נִשְׁאָר וּקְרָאָהוּ אָסוֹן בַּדֶּרֶךְ אֲשֶׁר תֵּלְכוּ־בָהּ וְהוֹרַדְתֶּם אֶת־שֵׂיבָתִי בְּיָגוֹן שְׁאוֹלָה׃

Chapter 43

וְהָרָעָב כָּבֵד בָּאָרֶץ׃
וַיְהִי כַּאֲשֶׁר כִּלּוּ לֶאֱכֹל אֶת־הַשֶּׁבֶר אֲשֶׁר הֵבִיאוּ מִמִּצְרָיִם וַיֹּאמֶר אֲלֵיהֶם אֲבִיהֶם שֻׁבוּ שִׁבְרוּ־לָנוּ מְעַט־אֹכֶל׃
וַיֹּאמֶר אֵלָיו יְהוּדָה לֵאמֹר הָעֵד הֵעִד בָּנוּ הָאִישׁ לֵאמֹר לֹא־תִרְאוּ פָנַי בִּלְתִּי אֲחִיכֶם אִתְּכֶם׃
אִם־יֶשְׁךָ מְשַׁלֵּחַ אֶת־אָחִינוּ אִתָּנוּ נֵרְדָה וְנִשְׁבְּרָה לְךָ אֹכֶל׃
וְאִם־אֵינְךָ מְשַׁלֵּחַ לֹא נֵרֵד כִּי־הָאִישׁ אָמַר אֵלֵינוּ לֹא־תִרְאוּ פָנַי בִּלְתִּי אֲחִיכֶם אִתְּכֶם׃
וַיֹּאמֶר יִשְׂרָאֵל לָמָה הֲרֵעֹתֶם לִי לְהַגִּיד לָאִישׁ הַעוֹד לָכֶם אָח׃
וַיֹּאמְרוּ שָׁאוֹל שָׁאַל־הָאִישׁ לָנוּ וּלְמוֹלַדְתֵּנוּ לֵאמֹר הַעוֹד אֲבִיכֶם חַי הֲיֵשׁ לָכֶם אָח וַנַגֶּד־לוֹ עַל־פִּי הַדְּבָרִים הָאֵלֶּה הֲיָדוֹעַ נֵדַע כִּי יֹאמַר הוֹרִידוּ אֶת־אֲחִיכֶם׃
וַיֹּאמֶר יְהוּדָה אֶל־יִשְׂרָאֵל אָבִיו שִׁלְחָה הַנַּעַר אִתִּי וְנָקוּמָה וְנֵלֵכָה וְנִחְיֶה וְלֹא נָמוּת גַּם־אֲנַחְנוּ גַם־אַתָּה גַּם־טַפֵּנוּ׃
אָנֹכִי אֶעֶרְבֶנּוּ מִיָּדִי תְּבַקְשֶׁנּוּ אִם־לֹא הֲבִיאֹתִיו אֵלֶיךָ וְהִצַּגְתִּיו לְפָנֶיךָ וְחָטָאתִי לְךָ כָּל־הַיָּמִים׃
כִּי לוּלֵא הִתְמַהְמָהְנוּ כִּי־עַתָּה שַׁבְנוּ זֶה פַעֲמָיִם׃
וַיֹּאמֶר אֲלֵהֶם יִשְׂרָאֵל אֲבִיהֶם אִם־כֵּן אֵפוֹא זֹאת עֲשׂוּ קְחוּ מִזִּמְרַת הָאָרֶץ בִּכְלֵיכֶם וְהוֹרִידוּ לָאִישׁ מִנְחָה מְעַט צֳרִי וּמְעַט דְּבַשׁ נְכֹאת וָלֹט בָּטְנִים וּשְׁקֵדִים׃
וְכֶסֶף מִשְׁנֶה קְחוּ בְיֶדְכֶם וְאֶת־הַכֶּסֶף הַמּוּשָׁב בְּפִי אַמְתְּחֹתֵיכֶם תָּשִׁיבוּ בְיֶדְכֶם אוּלַי מִשְׁגֶּה הוּא׃
וְאֶת־אֲחִיכֶם קָחוּ וְקוּמוּ שׁוּבוּ אֶל־הָאִישׁ׃
וְאֵל שַׁדַּי יִתֵּן לָכֶם רַחֲמִים לִפְנֵי הָאִישׁ וְשִׁלַּח לָכֶם אֶת־אֲחִיכֶם אַחֵר וְאֶת־בִּנְיָמִין וַאֲנִי כַּאֲשֶׁר שָׁכֹלְתִּי שָׁכָלְתִּי׃
וַיִּקְחוּ הָאֲנָשִׁים אֶת־הַמִּנְחָה הַזֹּאת וּמִשְׁנֶה־כֶּסֶף לָקְחוּ בְיָדָם וְאֶת־בִּנְיָמִן וַיָּקֻמוּ וַיֵּרְדוּ מִצְרַיִם וַיַּעַמְדוּ לִפְנֵי יוֹסֵף׃
וַיַּרְא יוֹסֵף אִתָּם אֶת־בִּנְיָמִין וַיֹּאמֶר לַאֲשֶׁר עַל־בֵּיתוֹ הָבֵא אֶת־הָאֲנָשִׁים הַבָּיְתָה וּטְבֹחַ טֶבַח וְהָכֵן כִּי אִתִּי יֹאכְלוּ הָאֲנָשִׁים בַּצָּהֳרָיִם׃
וַיַּעַשׂ הָאִישׁ כַּאֲשֶׁר אָמַר יוֹסֵף וַיָּבֵא הָאִישׁ אֶת־הָאֲנָשִׁים בֵּיתָה יוֹסֵף׃
וַיִּירְאוּ הָאֲנָשִׁים כִּי הוּבְאוּ בֵּית יוֹסֵף וַיֹּאמְרוּ עַל־דְּבַר הַכֶּסֶף הַשָּׁב בְּאַמְתְּחֹתֵינוּ בַּתְּחִלָּה אֲנַחְנוּ מוּבָאִים לְהִתְגֹּלֵל עָלֵינוּ וּלְהִתְנַפֵּל עָלֵינוּ וְלָקַחַת אֹתָנוּ לַעֲבָדִים וְאֶת־חֲמֹרֵינוּ׃
וַיִּגְּשׁוּ אֶל־הָאִישׁ אֲשֶׁר עַל־בֵּית יוֹסֵף וַיְדַבְּרוּ אֵלָיו פֶּתַח הַבָּיִת׃
וַיֹּאמְרוּ בִּי אֲדֹנִי יָרֹד יָרַדְנוּ בַּתְּחִלָּה לִשְׁבָּר־אֹכֶל׃
וַיְהִי כִּי־בָאנוּ אֶל־הַמָּלוֹן וַנִּפְתְּחָה אֶת־אַמְתְּחֹתֵינוּ וְהִנֵּה כֶסֶף־אִישׁ בְּפִי אַמְתַּחְתּוֹ כַּסְפֵּנוּ בְּמִשְׁקָלוֹ וַנָּשֶׁב אֹתוֹ בְּיָדֵנוּ׃
וְכֶסֶף אַחֵר הוֹרַדְנוּ בְיָדֵנוּ לִשְׁבָּר־אֹכֶל לֹא יָדַעְנוּ מִי־שָׂם כַּסְפֵּנוּ בְּאַמְתְּחֹתֵינוּ׃
וַיֹּאמֶר שָׁלוֹם לָכֶם אַל־תִּירָאוּ אֱלֹהֵיכֶם וֵאלֹהֵי אֲבִיכֶם נָתַן לָכֶם מַטְמוֹן בְּאַמְתְּחֹתֵיכֶם כַּסְפְּכֶם בָּא אֵלָי וַיּוֹצֵא אֲלֵהֶם אֶת־שִׁמְעוֹן׃
וַיָּבֵא הָאִישׁ אֶת־הָאֲנָשִׁים בֵּיתָה יוֹסֵף וַיִּתֶּן־מַיִם וַיִּרְחֲצוּ רַגְלֵיהֶם וַיִּתֵּן מִסְפּוֹא לַחֲמֹרֵיהֶם׃
וַיָּכִינוּ אֶת־הַמִּנְחָה עַד־בּוֹא יוֹסֵף בַּצָּהֳרָיִם כִּי שָׁמְעוּ כִּי־שָׁם יֹאכְלוּ לָחֶם׃
וַיָּבֹא יוֹסֵף הַבַּיְתָה וַיָּבִיאּוּ לוֹ אֶת־הַמִּנְחָה אֲשֶׁר־בְּיָדָם הַבָּיְתָה וַיִּשְׁתַּחֲווּ־לוֹ אָרְצָה׃
וַיִּשְׁאַל לָהֶם לְשָׁלוֹם וַיֹּאמֶר הֲשָׁלוֹם אֲבִיכֶם הַזָּקֵן אֲשֶׁר אֲמַרְתֶּם הַעוֹדֶנּוּ חָי׃
וַיֹּאמְרוּ שָׁלוֹם לְעַבְדְּךָ לְאָבִינוּ עוֹדֶנּוּ חָי וַיִּקְּדוּ וישתחו [וַיִּשְׁתַּחֲוּוּ׃]
וַיִּשָּׂא עֵינָיו וַיַּרְא אֶת־בִּנְיָמִין אָחִיו בֶּן־אִמּוֹ וַיֹּאמֶר הֲזֶה אֲחִיכֶם הַקָּטֹן אֲשֶׁר אֲמַרְתֶּם אֵלָי וַיֹּאמַר אֱלֹהִים יָחְנְךָ בְּנִי׃
וַיְמַהֵר יוֹסֵף כִּי־נִכְמְרוּ רַחֲמָיו אֶל־אָחִיו וַיְבַקֵּשׁ לִבְכּוֹת וַיָּבֹא הַחַדְרָה וַיֵּבְךְּ שָׁמָּה׃
וַיִּרְחַץ פָּנָיו וַיֵּצֵא וַיִּתְאַפַּק וַיֹּאמֶר שִׂימוּ לָחֶם׃
וַיָּשִׂימוּ לוֹ לְבַדּוֹ וְלָהֶם לְבַדָּם וְלַמִּצְרִים הָאֹכְלִים אִתּוֹ לְבַדָּם כִּי לֹא יוּכְלוּן הַמִּצְרִים לֶאֱכֹל אֶת־הָעִבְרִים לֶחֶם כִּי־תוֹעֵבָה הִוא לְמִצְרָיִם׃
וַיֵּשְׁבוּ לְפָנָיו הַבְּכֹר כִּבְכֹרָתוֹ וְהַצָּעִיר כִּצְעִרָתוֹ וַיִּתְמְהוּ הָאֲנָשִׁים אִישׁ אֶל־רֵעֵהוּ׃
וַיִּשָּׂא מַשְׂאֹת מֵאֵת פָּנָיו אֲלֵהֶם וַתֵּרֶב מַשְׂאַת בִּנְיָמִן מִמַּשְׂאֹת כֻּלָּם חָמֵשׁ יָדוֹת וַיִּשְׁתּוּ וַיִּשְׁכְּרוּ עִמּוֹ׃

Chapter 44

וַיְצַו אֶת־אֲשֶׁר עַל־בֵּיתוֹ לֵאמֹר מַלֵּא אֶת־אַמְתְּחֹת הָאֲנָשִׁים אֹכֶל כַּאֲשֶׁר יוּכְלוּן שְׂאֵת וְשִׂים כֶּסֶף־אִישׁ בְּפִי אַמְתַּחְתּוֹ׃
וְאֶת־גְּבִיעִי גְּבִיעַ הַכֶּסֶף תָּשִׂים בְּפִי אַמְתַּחַת הַקָּטֹן וְאֵת כֶּסֶף שִׁבְרוֹ וַיַּעַשׂ כִּדְבַר יוֹסֵף אֲשֶׁר דִּבֵּר׃
הַבֹּקֶר אוֹר וְהָאֲנָשִׁים שֻׁלְּחוּ הֵמָּה וַחֲמֹרֵיהֶם׃
הֵם יָצְאוּ אֶת־הָעִיר לֹא הִרְחִיקוּ וְיוֹסֵף אָמַר לַאֲשֶׁר עַל־בֵּיתוֹ קוּם רְדֹף אַחֲרֵי הָאֲנָשִׁים וְהִשַּׂגְתָּם וְאָמַרְתָּ אֲלֵהֶם לָמָּה שִׁלַּמְתֶּם רָעָה תַּחַת טוֹבָה׃
הֲלוֹא זֶה אֲשֶׁר יִשְׁתֶּה אֲדֹנִי בּוֹ וְהוּא נַחֵשׁ יְנַחֵשׁ בּוֹ הֲרֵעֹתֶם אֲשֶׁר עֲשִׂיתֶם׃
וַיַּשִּׂגֵם וַיְדַבֵּר אֲלֵהֶם אֶת־הַדְּבָרִים הָאֵלֶּה׃
וַיֹּאמְרוּ אֵלָיו לָמָּה יְדַבֵּר אֲדֹנִי כַּדְּבָרִים הָאֵלֶּה חָלִילָה לַעֲבָדֶיךָ מֵעֲשׂוֹת כַּדָּבָר הַזֶּה׃
הֵן כֶּסֶף אֲשֶׁר מָצָאנוּ בְּפִי אַמְתְּחֹתֵינוּ הֱשִׁיבֹנוּ אֵלֶיךָ מֵאֶרֶץ כְּנָעַן וְאֵיךְ נִגְנֹב מִבֵּית אֲדֹנֶיךָ כֶּסֶף אוֹ זָהָב׃
אֲשֶׁר יִמָּצֵא אִתּוֹ מֵעֲבָדֶיךָ וָמֵת וְגַם־אֲנַחְנוּ נִהְיֶה לַאדֹנִי לַעֲבָדִים׃
וַיֹּאמֶר גַּם־עַתָּה כְדִבְרֵיכֶם כֶּן־הוּא אֲשֶׁר יִמָּצֵא אִתּוֹ יִהְיֶה־לִּי עָבֶד וְאַתֶּם תִּהְיוּ נְקִיִּם׃
וַיְמַהֲרוּ וַיּוֹרִדוּ אִישׁ אֶת־אַמְתַּחְתּוֹ אָרְצָה וַיִּפְתְּחוּ אִישׁ אַמְתַּחְתּוֹ׃
וַיְחַפֵּשׂ בַּגָּדוֹל הֵחֵל וּבַקָּטֹן כִּלָּה וַיִּמָּצֵא הַגָּבִיעַ בְּאַמְתַּחַת בִּנְיָמִן׃
וַיִּקְרְעוּ שִׂמְלֹתָם וַיַּעֲמֹס אִישׁ עַל־חֲמֹרוֹ וַיָּשֻׁבוּ הָעִירָה׃
וַיָּבֹא יְהוּדָה וְאֶחָיו בֵּיתָה יוֹסֵף וְהוּא עוֹדֶנּוּ שָׁם וַיִּפְּלוּ לְפָנָיו אָרְצָה׃
וַיֹּאמֶר לָהֶם יוֹסֵף מָה־הַמַּעֲשֶׂה הַזֶּה אֲשֶׁר עֲשִׂיתֶם הֲלוֹא יְדַעְתֶּם כִּי־נַחֵשׁ יְנַחֵשׁ אִישׁ אֲשֶׁר כָּמֹנִי׃
וַיֹּאמֶר יְהוּדָה מַה־נֹּאמַר לַאדֹנִי מַה־נְּדַבֵּר וּמַה־נִּצְטַדָּק הָאֱלֹהִים מָצָא אֶת־עֲוֺן עֲבָדֶיךָ הִנֶּנּוּ עֲבָדִים לַאדֹנִי גַּם־אֲנַחְנוּ גַּם אֲשֶׁר־נִמְצָא הַגָּבִיעַ בְּיָדוֹ׃
וַיֹּאמֶר חָלִילָה לִּי מֵעֲשׂוֹת זֹאת הָאִישׁ אֲשֶׁר נִמְצָא הַגָּבִיעַ בְּיָדוֹ הוּא יִהְיֶה־לִּי עָבֶד וְאַתֶּם עֲלוּ לְשָׁלוֹם אֶל־אֲבִיכֶם׃
וַיִּגַּשׁ אֵלָיו יְהוּדָה וַיֹּאמֶר בִּי אֲדֹנִי יְדַבֶּר־נָא עַבְדְּךָ דָבָר בְּאָזְנֵי אֲדֹנִי וְאַל־יִחַר אַפְּךָ בְּעַבְדֶּךָ כִּי כָמוֹךָ כְּפַרְעֹה׃
אֲדֹנִי שָׁאַל אֶת־עֲבָדָיו לֵאמֹר הֲיֵשׁ־לָכֶם אָב אוֹ־אָח׃
וַנֹּאמֶר אֶל־אֲדֹנִי יֶשׁ־לָנוּ אָב זָקֵן וְיֶלֶד זְקֻנִים קָטָן וְאָחִיו מֵת וַיִּוָּתֵר הוּא לְבַדּוֹ לְאִמּוֹ וְאָבִיו אֲהֵבוֹ׃
וַתֹּאמֶר אֶל־עֲבָדֶיךָ הוֹרִדֻהוּ אֵלָי וְאָשִׂימָה עֵינִי עָלָיו׃
וַנֹּאמֶר אֶל־אֲדֹנִי לֹא־יוּכַל הַנַּעַר לַעֲזֹב אֶת־אָבִיו וְעָזַב אֶת־אָבִיו וָמֵת׃
וַתֹּאמֶר אֶל־עֲבָדֶיךָ אִם־לֹא יֵרֵד אֲחִיכֶם הַקָּטֹן אִתְּכֶם לֹא תֹסִפוּן לִרְאוֹת פָּנָי׃
וַיְהִי כִּי עָלִינוּ אֶל־עַבְדְּךָ אָבִי וַנַּגֶּד־לוֹ אֵת דִּבְרֵי אֲדֹנִי׃
וַיֹּאמֶר אָבִינוּ שֻׁבוּ שִׁבְרוּ־לָנוּ מְעַט־אֹכֶל׃
וַנֹּאמֶר לֹא נוּכַל לָרֶדֶת אִם־יֵשׁ אָחִינוּ הַקָּטֹן אִתָּנוּ וְיָרַדְנוּ כִּי־לֹא נוּכַל לִרְאוֹת פְּנֵי הָאִישׁ וְאָחִינוּ הַקָּטֹן אֵינֶנּוּ אִתָּנוּ׃
וַיֹּאמֶר עַבְדְּךָ אָבִי אֵלֵינוּ אַתֶּם יְדַעְתֶּם כִּי שְׁנַיִם יָלְדָה־לִּי אִשְׁתִּי׃
וַיֵּצֵא הָאֶחָד מֵאִתִּי וָאֹמַר אַךְ טָרֹף טֹרָף וְלֹא רְאִיתִיו עַד־הֵנָּה׃
וּלְקַחְתֶּם גַּם־אֶת־זֶה מֵעִם פָּנַי וְקָרָהוּ אָסוֹן וְהוֹרַדְתֶּם אֶת־שֵׂיבָתִי בְּרָעָה שְׁאֹלָה׃
וְעַתָּה כְּבֹאִי אֶל־עַבְדְּךָ אָבִי וְהַנַּעַר אֵינֶנּוּ אִתָּנוּ וְנַפְשׁוֹ קְשׁוּרָה בְנַפְשׁוֹ׃
וְהָיָה כִּרְאוֹתוֹ כִּי־אֵין הַנַּעַר וָמֵת וְהוֹרִידוּ עֲבָדֶיךָ אֶת־שֵׂיבַת עַבְדְּךָ אָבִינוּ בְּיָגוֹן שְׁאֹלָה׃
כִּי עַבְדְּךָ עָרַב אֶת־הַנַּעַר מֵעִם אָבִי לֵאמֹר אִם־לֹא אֲבִיאֶנּוּ אֵלֶיךָ וְחָטָאתִי לְאָבִי כָּל־הַיָּמִים׃
וְעַתָּה יֵשֶׁב־נָא עַבְדְּךָ תַּחַת הַנַּעַר עֶבֶד לַאדֹנִי וְהַנַּעַר יַעַל עִם־אֶחָיו׃
כִּי־אֵיךְ אֶעֱלֶה אֶל־אָבִי וְהַנַּעַר אֵינֶנּוּ אִתִּי פֶּן אֶרְאֶה בָרָע אֲשֶׁר יִמְצָא אֶת־אָבִי׃

Chapter 45

וְלֹא־יָכֹל יוֹסֵף לְהִתְאַפֵּק לְכֹל הַנִּצָּבִים עָלָיו וַיִּקְרָא הוֹצִיאוּ כָל־אִישׁ מֵעָלָי וְלֹא־עָמַד אִישׁ אִתּוֹ בְּהִתְוַדַּע יוֹסֵף אֶל־אֶחָיו׃
וַיִּתֵּן אֶת־קֹלוֹ בִּבְכִי וַיִּשְׁמְעוּ מִצְרַיִם וַיִּשְׁמַע בֵּית פַּרְעֹה׃
וַיֹּאמֶר יוֹסֵף אֶל־אֶחָיו אֲנִי יוֹסֵף הַעוֹד אָבִי חָי וְלֹא־יָכְלוּ אֶחָיו לַעֲנוֹת אֹתוֹ כִּי נִבְהֲלוּ מִפָּנָיו׃
וַיֹּאמֶר יוֹסֵף אֶל־אֶחָיו גְּשׁוּ־נָא אֵלַי וַיִּגָּשׁוּ וַיֹּאמֶר אֲנִי יוֹסֵף אֲחִיכֶם אֲשֶׁר־מְכַרְתֶּם אֹתִי מִצְרָיְמָה׃
וְעַתָּה אַל־תֵּעָצְבוּ וְאַל־יִחַר בְּעֵינֵיכֶם כִּי־מְכַרְתֶּם אֹתִי הֵנָּה כִּי לְמִחְיָה שְׁלָחַנִי אֱלֹהִים לִפְנֵיכֶם׃
כִּי־זֶה שְׁנָתַיִם הָרָעָב בְּקֶרֶב הָאָרֶץ וְעוֹד חָמֵשׁ שָׁנִים אֲשֶׁר אֵין־חָרִישׁ וְקָצִּיר׃
וַיִּשְׁלָחֵנִי אֱלֹהִים לִפְנֵיכֶם לָשׂוּם לָכֶם שְׁאֵרִית בָּאָרֶץ וּלְהַחֲיוֹת לָכֶם לִפְלֵיטָה גְּדֹלָה׃
וְעַתָּה לֹא־אַתֶּם שְׁלַחְתֶּם אֹתִי הֵנָּה כִּי הָאֱלֹהִים וַיְשִׂימֵנִי לְאָב לְפַרְעֹה וּלְאָדוֹן לְכָל־בֵּיתוֹ וּמֹשֵׁל בְּכָל־אֶרֶץ מִצְרָיִם׃
מַהֲרוּ וַעֲלוּ אֶל־אָבִי וַאֲמַרְתֶּם אֵלָיו כֹּה אָמַר בִּנְךָ יוֹסֵף שָׂמַנִי אֱלֹהִים לְאָדוֹן לְכָל־מִצְרָיִם רְדָה אֵלַי אַל־תַּעֲמֹד׃
וְיָשַׁבְתָּ בְאֶרֶץ־גֹּשֶׁן וְהָיִיתָ קָרוֹב אֵלַי אַתָּה וּבָנֶיךָ וּבְנֵי בָנֶיךָ וְצֹאנְךָ וּבְקָרְךָ וְכָל־אֲשֶׁר־לָךְ׃
וְכִלְכַּלְתִּי אֹתְךָ שָׁם כִּי־עוֹד חָמֵשׁ שָׁנִים רָעָב פֶּן־תִּוָּרֵשׁ אַתָּה וּבֵיתְךָ וְכָל־אֲשֶׁר־לָךְ׃
וְהִנֵּה עֵינֵיכֶם רֹאוֹת וְעֵינֵי אָחִי בִנְיָמִין כִּי־פִי הַמְדַבֵּר אֲלֵיכֶם׃
וְהִגַּדְתֶּם לְאָבִי אֶת־כָּל־כְּבוֹדִי בְּמִצְרַיִם וְאֵת כָּל־אֲשֶׁר רְאִיתֶם וּמִהַרְתֶּם וְהוֹרַדְתֶּם אֶת־אָבִי הֵנָּה׃
וַיִּפֹּל עַל־צַוְּארֵי בִנְיָמִן־אָחִיו וַיֵּבְךְּ וּבִנְיָמִן בָּכָה עַל־צַוָּארָיו׃
וַיְנַשֵּׁק לְכָל־אֶחָיו וַיֵּבְךְּ עֲלֵיהֶם וְאַחֲרֵי כֵן דִּבְּרוּ אֶחָיו אִתּוֹ׃
וְהַקֹּל נִשְׁמַע בֵּית פַּרְעֹה לֵאמֹר בָּאוּ אֲחֵי יוֹסֵף וַיִּיטַב בְּעֵינֵי פַרְעֹה וּבְעֵינֵי עֲבָדָיו׃
וַיֹּאמֶר פַּרְעֹה אֶל־יוֹסֵף אֱמֹר אֶל־אַחֶיךָ זֹאת עֲשׂוּ טַעֲנוּ אֶת־בְּעִירְכֶם וּלְכוּ־בֹאוּ אַרְצָה כְּנָעַן׃
וּקְחוּ אֶת־אֲבִיכֶם וְאֶת־בָּתֵּיכֶם וּבֹאוּ אֵלָי וְאֶתְּנָה לָכֶם אֶת־טוּב אֶרֶץ מִצְרַיִם וְאִכְלוּ אֶת־חֵלֶב הָאָרֶץ׃
וְאַתָּה צֻוֵּיתָה זֹאת עֲשׂוּ קְחוּ־לָכֶם מֵאֶרֶץ מִצְרַיִם עֲגָלוֹת לְטַפְּכֶם וְלִנְשֵׁיכֶם וּנְשָׂאתֶם אֶת־אֲבִיכֶם וּבָאתֶם׃
וְעֵינְכֶם אַל־תָּחֹס עַל־כְּלֵיכֶם כִּי־טוּב כָּל־אֶרֶץ מִצְרַיִם לָכֶם הוּא׃
וַיַּעֲשׂוּ־כֵן בְּנֵי יִשְׂרָאֵל וַיִּתֵּן לָהֶם יוֹסֵף עֲגָלוֹת עַל־פִּי פַרְעֹה וַיִּתֵּן לָהֶם צֵדָה לַדָּרֶךְ׃
לְכֻלָּם נָתַן לָאִישׁ חֲלִפוֹת שְׂמָלֹת וּלְבִנְיָמִן נָתַן שְׁלֹשׁ מֵאוֹת כֶּסֶף וְחָמֵשׁ חֲלִפֹת שְׂמָלֹת׃
וּלְאָבִיו שָׁלַח כְּזֹאת עֲשָׂרָה חֲמֹרִים נֹשְׂאִים מִטּוּב מִצְרָיִם וְעֶשֶׂר אֲתֹנֹת נֹשְׂאֹת בָּר וָלֶחֶם וּמָזוֹן לְאָבִיו לַדָּרֶךְ׃
וַיְשַׁלַּח אֶת־אֶחָיו וַיֵּלֵכוּ וַיֹּאמֶר אֲלֵהֶם אַל־תִּרְגְּזוּ בַּדָּרֶךְ׃
וַיַּעֲלוּ מִמִּצְרָיִם וַיָּבֹאוּ אֶרֶץ כְּנַעַן אֶל־יַעֲקֹב אֲבִיהֶם׃
וַיַּגִּדוּ לוֹ לֵאמֹר עוֹד יוֹסֵף חַי וְכִי־הוּא מֹשֵׁל בְּכָל־אֶרֶץ מִצְרָיִם וַיָּפָג לִבּוֹ כִּי לֹא־הֶאֱמִין לָהֶם׃
וַיְדַבְּרוּ אֵלָיו אֵת כָּל־דִּבְרֵי יוֹסֵף אֲשֶׁר דִּבֶּר אֲלֵהֶם וַיַּרְא אֶת־הָעֲגָלוֹת אֲשֶׁר־שָׁלַח יוֹסֵף לָשֵׂאת אֹתוֹ וַתְּחִי רוּחַ יַעֲקֹב אֲבִיהֶם׃
וַיֹּאמֶר יִשְׂרָאֵל רַב עוֹד־יוֹסֵף בְּנִי חָי אֵלְכָה וְאֶרְאֶנּוּ בְּטֶרֶם אָמוּת׃

Chapter 46

וַיִּסַּע יִשְׂרָאֵל וְכָל־אֲשֶׁר־לוֹ וַיָּבֹא בְּאֵרָה שָּׁבַע וַיִּזְבַּח זְבָחִים לֵאלֹהֵי אָבִיו יִצְחָק׃
וַיֹּאמֶר אֱלֹהִים לְיִשְׂרָאֵל בְּמַרְאֹת הַלַּיְלָה וַיֹּאמֶר יַעֲקֹב יַעֲקֹב וַיֹּאמֶר הִנֵּנִי׃
וַיֹּאמֶר אָנֹכִי הָאֵל אֱלֹהֵי אָבִיךָ אַל־תִּירָא מֵרְדָה מִצְרַיְמָה כִּי־לְגוֹי גָּדוֹל אֲשִׂימְךָ שָׁם׃
אָנֹכִי אֵרֵד עִמְּךָ מִצְרַיְמָה וְאָנֹכִי אַעַלְךָ גַם־עָלֹה וְיוֹסֵף יָשִׁית יָדוֹ עַל־עֵינֶיךָ׃
וַיָּקָם יַעֲקֹב מִבְּאֵר שָׁבַע וַיִּשְׂאוּ בְנֵי־יִשְׂרָאֵל אֶת־יַעֲקֹב אֲבִיהֶם וְאֶת־טַפָּם וְאֶת־נְשֵׁיהֶם בָּעֲגָלוֹת אֲשֶׁר־שָׁלַח פַּרְעֹה לָשֵׂאת אֹתוֹ׃
וַיִּקְחוּ אֶת־מִקְנֵיהֶם וְאֶת־רְכוּשָׁם אֲשֶׁר רָכְשׁוּ בְּאֶרֶץ כְּנַעַן וַיָּבֹאוּ מִצְרָיְמָה יַעֲקֹב וְכָל־זַרְעוֹ אִתּוֹ׃
בָּנָיו וּבְנֵי בָנָיו אִתּוֹ בְּנֹתָיו וּבְנוֹת בָּנָיו וְכָל־זַרְעוֹ הֵבִיא אִתּוֹ מִצְרָיְמָה׃
וְאֵלֶּה שְׁמוֹת בְּנֵי־יִשְׂרָאֵל הַבָּאִים מִצְרַיְמָה יַעֲקֹב וּבָנָיו בְּכֹר יַעֲקֹב רְאוּבֵן׃
וּבְנֵי רְאוּבֵן חֲנוֹךְ וּפַלּוּא וְחֶצְרוֹן וְכַרְמִי׃
וּבְנֵי שִׁמְעוֹן יְמוּאֵל וְיָמִין וְאֹהַד וְיָכִין וְצֹחַר וְשָׁאוּל בֶּן־הַכְּנַעֲנִית׃
וּבְנֵי לֵוִי גֵּרְשׁוֹן קְהָת וּמְרָרִי׃
וּבְנֵי יְהוּדָה עֵר וְאוֹנָן וְשֵׁלָה וָפֶרֶץ וָזָרַח וַיָּמָת עֵר וְאוֹנָן בְּאֶרֶץ כְּנַעַן וַיִּהְיוּ בְנֵי־פֶרֶץ חֶצְרוֹן וְחָמוּל׃
וּבְנֵי יִשָׂשכָר תּוֹלָע וּפֻוָּה וְיוֹב וְשִׁמְרוֹן׃
וּבְנֵי זְבוּלֻן סֶרֶד וְאֵלוֹן וְיַחְלְאֵל׃
אֵלֶּה בְּנֵי לֵאָה אֲשֶׁר יָלְדָה לְיַעֲקֹב בְּפַדַּן אֲרָם וְאֵת דִּינָה בִתּוֹ כָּל־נֶפֶשׁ בָּנָיו וּבְנוֹתָיו שְׁלֹשִׁים וְשָׁלֹשׁ׃
וּבְנֵי גָד צִפְיוֹן וְחַגִּי שׁוּנִי וְאֶצְבֹּן עֵרִי וַאֲרוֹדִי וְאַרְאֵלִי׃
וּבְנֵי אָשֵׁר יִמְנָה וְיִשְׁוָה וְיִשְׁוִי וּבְרִיעָה וְשֶׂרַח אֲחֹתָם וּבְנֵי בְרִיעָה חֶבֶר וּמַלְכִּיאֵל׃
אֵלֶּה בְּנֵי זִלְפָּה אֲשֶׁר־נָתַן לָבָן לְלֵאָה בִתּוֹ וַתֵּלֶד אֶת־אֵלֶּה לְיַעֲקֹב שֵׁשׁ עֶשְׂרֵה נָפֶשׁ׃
בְּנֵי רָחֵל אֵשֶׁת יַעֲקֹב יוֹסֵף וּבִנְיָמִן׃
וַיִּוָּלֵד לְיוֹסֵף בְּאֶרֶץ מִצְרַיִם אֲשֶׁר יָלְדָה־לּוֹ אָסְנַת בַּת־פּוֹטִי פֶרַע כֹּהֵן אֹן אֶת־מְנַשֶּׁה וְאֶת־אֶפְרָיִם׃
וּבְנֵי בִנְיָמִן בֶּלַע וָבֶכֶר וְאַשְׁבֵּל גֵּרָא וְנַעֲמָן אֵחִי וָרֹאשׁ מֻפִּים וְחֻפִּים וָאָרְדְּ׃
אֵלֶּה בְּנֵי רָחֵל אֲשֶׁר יֻלַּד לְיַעֲקֹב כָּל־נֶפֶשׁ אַרְבָּעָה עָשָׂר׃
וּבְנֵי־דָן חֻשִׁים׃
וּבְנֵי נַפְתָּלִי יַחְצְאֵל וְגוּנִי וְיֵצֶר וְשִׁלֵּם׃
אֵלֶּה בְּנֵי בִלְהָה אֲשֶׁר־נָתַן לָבָן לְרָחֵל בִּתּוֹ וַתֵּלֶד אֶת־אֵלֶּה לְיַעֲקֹב כָּל־נֶפֶשׁ שִׁבְעָה׃
כָּל־הַנֶּפֶשׁ הַבָּאָה לְיַעֲקֹב מִצְרַיְמָה יֹצְאֵי יְרֵכוֹ מִלְּבַד נְשֵׁי בְנֵי־יַעֲקֹב כָּל־נֶפֶשׁ שִׁשִּׁים וָשֵׁשׁ׃
וּבְנֵי יוֹסֵף אֲשֶׁר־יֻלַּד־לוֹ בְמִצְרַיִם נֶפֶשׁ שְׁנָיִם כָּל־הַנֶּפֶשׁ לְבֵית־יַעֲקֹב הַבָּאָה מִצְרַיְמָה שִׁבְעִים׃
וְאֶת־יְהוּדָה שָׁלַח לְפָנָיו אֶל־יוֹסֵף לְהוֹרֹת לְפָנָיו גֹּשְׁנָה וַיָּבֹאוּ אַרְצָה גֹּשֶׁן׃
וַיֶּאְסֹר יוֹסֵף מֶרְכַּבְתּוֹ וַיַּעַל לִקְרַאת־יִשְׂרָאֵל אָבִיו גֹּשְׁנָה וַיֵּרָא אֵלָיו וַיִּפֹּל עַל־צַוָּארָיו וַיֵּבְךְּ עַל־צַוָּארָיו עוֹד׃
וַיֹּאמֶר יִשְׂרָאֵל אֶל־יוֹסֵף אָמוּתָה הַפָּעַם אַחֲרֵי רְאוֹתִי אֶת־פָּנֶיךָ כִּי עוֹדְךָ חָי׃
וַיֹּאמֶר יוֹסֵף אֶל־אֶחָיו וְאֶל־בֵּית אָבִיו אֶעֱלֶה וְאַגִּידָה לְפַרְעֹה וְאֹמְרָה אֵלָיו אַחַי וּבֵית־אָבִי אֲשֶׁר בְּאֶרֶץ־כְּנַעַן בָּאוּ אֵלָי׃
וְהָאֲנָשִׁים רֹעֵי צֹאן כִּי־אַנְשֵׁי מִקְנֶה הָיוּ וְצֹאנָם וּבְקָרָם וְכָל־אֲשֶׁר לָהֶם הֵבִיאוּ׃
וְהָיָה כִּי־יִקְרָא לָכֶם פַּרְעֹה וְאָמַר מַה־מַּעֲשֵׂיכֶם׃
וַאֲמַרְתֶּם אַנְשֵׁי מִקְנֶה הָיוּ עֲבָדֶיךָ מִנְּעוּרֵינוּ וְעַד־עַתָּה גַּם־אֲנַחְנוּ גַּם־אֲבֹתֵינוּ בַּעֲבוּר תֵּשְׁבוּ בְּאֶרֶץ גֹּשֶׁן כִּי־תוֹעֲבַת מִצְרַיִם כָּל־רֹעֵה צֹאן׃

Chapter 47

וַיָּבֹא יוֹסֵף וַיַּגֵּד לְפַרְעֹה וַיֹּאמֶר אָבִי וְאַחַי וְצֹאנָם וּבְקָרָם וְכָל־אֲשֶׁר לָהֶם בָּאוּ מֵאֶרֶץ כְּנָעַן וְהִנָּם בְּאֶרֶץ גֹּשֶׁן׃
וּמִקְצֵה אֶחָיו לָקַח חֲמִשָּׁה אֲנָשִׁים וַיַּצִּגֵם לִפְנֵי פַרְעֹה׃
וַיֹּאמֶר פַּרְעֹה אֶל־אֶחָיו מַה־מַּעֲשֵׂיכֶם וַיֹּאמְרוּ אֶל־פַּרְעֹה רֹעֵה צֹאן עֲבָדֶיךָ גַּם־אֲנַחְנוּ גַּם־אֲבוֹתֵינוּ׃
וַיֹּאמְרוּ אֶל־פַּרְעֹה לָגוּר בָּאָרֶץ בָּאנוּ כִּי־אֵין מִרְעֶה לַצֹּאן אֲשֶׁר לַעֲבָדֶיךָ כִּי־כָבֵד הָרָעָב בְּאֶרֶץ כְּנָעַן וְעַתָּה יֵשְׁבוּ־נָא עֲבָדֶיךָ בְּאֶרֶץ גֹּשֶׁן׃
וַיֹּאמֶר פַּרְעֹה אֶל־יוֹסֵף לֵאמֹר אָבִיךָ וְאַחֶיךָ בָּאוּ אֵלֶיךָ׃
אֶרֶץ מִצְרַיִם לְפָנֶיךָ הִוא בְּמֵיטַב הָאָרֶץ הוֹשֵׁב אֶת־אָבִיךָ וְאֶת־אַחֶיךָ יֵשְׁבוּ בְּאֶרֶץ גֹּשֶׁן וְאִם־יָדַעְתָּ וְיֶשׁ־בָּם אַנְשֵׁי־חַיִל וְשַׂמְתָּם שָׂרֵי מִקְנֶה עַל־אֲשֶׁר־לִי׃
וַיָּבֵא יוֹסֵף אֶת־יַעֲקֹב אָבִיו וַיַּעֲמִדֵהוּ לִפְנֵי פַרְעֹה וַיְבָרֶךְ יַעֲקֹב אֶת־פַּרְעֹה׃
וַיֹּאמֶר פַּרְעֹה אֶל־יַעֲקֹב כַּמָּה יְמֵי שְׁנֵי חַיֶּיךָ׃
וַיֹּאמֶר יַעֲקֹב אֶל־פַּרְעֹה יְמֵי שְׁנֵי מְגוּרַי שְׁלֹשִׁים וּמְאַת שָׁנָה מְעַט וְרָעִים הָיוּ יְמֵי שְׁנֵי חַיַּי וְלֹא הִשִּׂיגוּ אֶת־יְמֵי שְׁנֵי חַיֵּי אֲבֹתַי בִּימֵי מְגוּרֵיהֶם׃
וַיְבָרֶךְ יַעֲקֹב אֶת־פַּרְעֹה וַיֵּצֵא מִלִּפְנֵי פַרְעֹה׃
וַיּוֹשֵׁב יוֹסֵף אֶת־אָבִיו וְאֶת־אֶחָיו וַיִּתֵּן לָהֶם אֲחֻזָּה בְּאֶרֶץ מִצְרַיִם בְּמֵיטַב הָאָרֶץ בְּאֶרֶץ רַעְמְסֵס כַּאֲשֶׁר צִוָּה פַרְעֹה׃
וַיְכַלְכֵּל יוֹסֵף אֶת־אָבִיו וְאֶת־אֶחָיו וְאֵת כָּל־בֵּית אָבִיו לֶחֶם לְפִי הַטָּף׃
וְלֶחֶם אֵין בְּכָל־הָאָרֶץ כִּי־כָבֵד הָרָעָב מְאֹד וַתֵּלַהּ אֶרֶץ מִצְרַיִם וְאֶרֶץ כְּנַעַן מִפְּנֵי הָרָעָב׃
וַיְלַקֵּט יוֹסֵף אֶת־כָּל־הַכֶּסֶף הַנִּמְצָא בְאֶרֶץ־מִצְרַיִם וּבְאֶרֶץ כְּנַעַן בַּשֶּׁבֶר אֲשֶׁר־הֵם שֹׁבְרִים וַיָּבֵא יוֹסֵף אֶת־הַכֶּסֶף בֵּיתָה פַרְעֹה׃
וַיִּתֹּם הַכֶּסֶף מֵאֶרֶץ מִצְרַיִם וּמֵאֶרֶץ כְּנַעַן וַיָּבֹאוּ כָל־מִצְרַיִם אֶל־יוֹסֵף לֵאמֹר הָבָה־לָּנוּ לֶחֶם וְלָמָּה נָמוּת נֶגְדֶּךָ כִּי אָפֵס כָּסֶף׃
וַיֹּאמֶר יוֹסֵף הָבוּ מִקְנֵיכֶם וְאֶתְּנָה לָכֶם בְּמִקְנֵיכֶם אִם־אָפֵס כָּסֶף׃
וַיָּבִיאוּ אֶת־מִקְנֵיהֶם אֶל־יוֹסֵף וַיִּתֵּן לָהֶם יוֹסֵף לֶחֶם בַּסּוּסִים וּבְמִקְנֵה הַצֹּאן וּבְמִקְנֵה הַבָּקָר וּבַחֲמֹרִים וַיְנַהֲלֵם בַּלֶּחֶם בְּכָל־מִקְנֵהֶם בַּשָּׁנָה הַהִוא׃
וַתִּתֹּם הַשָּׁנָה הַהִוא וַיָּבֹאוּ אֵלָיו בַּשָּׁנָה הַשֵּׁנִית וַיֹּאמְרוּ לוֹ לֹא־נְכַחֵד מֵאֲדֹנִי כִּי אִם־תַּם הַכֶּסֶף וּמִקְנֵה הַבְּהֵמָה אֶל־אֲדֹנִי לֹא נִשְׁאַר לִפְנֵי אֲדֹנִי בִּלְתִּי אִם־גְּוִיָּתֵנוּ וְאַדְמָתֵנוּ׃
לָמָּה נָמוּת לְעֵינֶיךָ גַּם־אֲנַחְנוּ גַּם אַדְמָתֵנוּ קְנֵה־אֹתָנוּ וְאֶת־אַדְמָתֵנוּ בַּלָּחֶם וְנִהְיֶה אֲנַחְנוּ וְאַדְמָתֵנוּ עֲבָדִים לְפַרְעֹה וְתֶן־זֶרַע וְנִחְיֶה וְלֹא נָמוּת וְהָאֲדָמָה לֹא תֵשָׁם׃
וַיִּקֶן יוֹסֵף אֶת־כָּל־אַדְמַת מִצְרַיִם לְפַרְעֹה כִּי־מָכְרוּ מִצְרַיִם אִישׁ שָׂדֵהוּ כִּי־חָזַק עֲלֵהֶם הָרָעָב וַתְּהִי הָאָרֶץ לְפַרְעֹה׃
וְאֶת־הָעָם הֶעֱבִיר אֹתוֹ לֶעָרִים מִקְצֵה גְבוּל־מִצְרַיִם וְעַד־קָצֵהוּ׃
רַק אַדְמַת הַכֹּהֲנִים לֹא קָנָה כִּי חֹק לַכֹּהֲנִים מֵאֵת פַּרְעֹה וְאָכְלוּ אֶת־חֻקָּם אֲשֶׁר נָתַן לָהֶם פַּרְעֹה עַל־כֵּן לֹא מָכְרוּ אֶת־אַדְמָתָם׃
וַיֹּאמֶר יוֹסֵף אֶל־הָעָם הֵן קָנִיתִי אֶתְכֶם הַיּוֹם וְאֶת־אַדְמַתְכֶם לְפַרְעֹה הֵא־לָכֶם זֶרַע וּזְרַעְתֶּם אֶת־הָאֲדָמָה׃
וְהָיָה בַּתְּבוּאֹת וּנְתַתֶּם חֲמִישִׁית לְפַרְעֹה וְאַרְבַּע הַיָּדֹת יִהְיֶה לָכֶם לְזֶרַע הַשָּׂדֶה וּלְאָכְלְכֶם וְלַאֲשֶׁר בְּבָתֵּיכֶם וְלֶאֱכֹל לְטַפְּכֶם׃
וַיֹּאמְרוּ הֶחֱיִתָנוּ נִמְצָא־חֵן בְּעֵינֵי אֲדֹנִי וְהָיִינוּ עֲבָדִים לְפַרְעֹה׃
וַיָּשֶׂם אֹתָהּ יוֹסֵף לְחֹק עַד־הַיּוֹם הַזֶּה עַל־אַדְמַת מִצְרַיִם לְפַרְעֹה לַחֹמֶשׁ רַק אַדְמַת הַכֹּהֲנִים לְבַדָּם לֹא הָיְתָה לְפַרְעֹה׃
וַיֵּשֶׁב יִשְׂרָאֵל בְּאֶרֶץ מִצְרַיִם בְּאֶרֶץ גֹּשֶׁן וַיֵּאָחֲזוּ בָהּ וַיִּפְרוּ וַיִּרְבּוּ מְאֹד׃
וַיְחִי יַעֲקֹב בְּאֶרֶץ מִצְרַיִם שְׁבַע עֶשְׂרֵה שָׁנָה וַיְהִי יְמֵי־יַעֲקֹב שְׁנֵי חַיָּיו שֶׁבַע שָׁנִים וְאַרְבָּעִים וּמְאַת שָׁנָה׃
וַיִּקְרְבוּ יְמֵי־יִשְׂרָאֵל לָמוּת וַיִּקְרָא לִבְנוֹ לְיוֹסֵף וַיֹּאמֶר לוֹ אִם־נָא מָצָאתִי חֵן בְּעֵינֶיךָ שִׂים־נָא יָדְךָ תַּחַת יְרֵכִי וְעָשִׂיתָ עִמָּדִי חֶסֶד וֶאֱמֶת אַל־נָא תִקְבְּרֵנִי בְּמִצְרָיִם׃
וְשָׁכַבְתִּי עִם־אֲבֹתַי וּנְשָׂאתַנִי מִמִּצְרַיִם וּקְבַרְתַּנִי בִּקְבֻרָתָם וַיֹּאמַר אָנֹכִי אֶעֱשֶׂה כִדְבָרֶךָ׃
וַיֹּאמֶר הִשָּׁבְעָה לִי וַיִּשָּׁבַע לוֹ וַיִּשְׁתַּחוּ יִשְׂרָאֵל עַל־רֹאשׁ הַמִּטָּה׃

Chapter 48

וַיְהִי אַחֲרֵי הַדְּבָרִים הָאֵלֶּה וַיֹּאמֶר לְיוֹסֵף הִנֵּה אָבִיךָ חֹלֶה וַיִּקַּח אֶת־שְׁנֵי בָנָיו עִמּוֹ אֶת־מְנַשֶּׁה וְאֶת־אֶפְרָיִם׃
וַיַּגֵּד לְיַעֲקֹב וַיֹּאמֶר הִנֵּה בִּנְךָ יוֹסֵף בָּא אֵלֶיךָ וַיִּתְחַזֵּק יִשְׂרָאֵל וַיֵּשֶׁב עַל־הַמִּטָּה׃
וַיֹּאמֶר יַעֲקֹב אֶל־יוֹסֵף אֵל שַׁדַּי נִרְאָה־אֵלַי בְּלוּז בְּאֶרֶץ כְּנָעַן וַיְבָרֶךְ אֹתִי׃
וַיֹּאמֶר אֵלַי הִנְנִי מַפְרְךָ וְהִרְבִּיתִךָ וּנְתַתִּיךָ לִקְהַל עַמִּים וְנָתַתִּי אֶת־הָאָרֶץ הַזֹּאת לְזַרְעֲךָ אַחֲרֶיךָ אֲחֻזַּת עוֹלָם׃
וְעַתָּה שְׁנֵי־בָנֶיךָ הַנּוֹלָדִים לְךָ בְּאֶרֶץ מִצְרַיִם עַד־בֹּאִי אֵלֶיךָ מִצְרַיְמָה לִי־הֵם אֶפְרַיִם וּמְנַשֶּׁה כִּרְאוּבֵן וְשִׁמְעוֹן יִהְיוּ־לִי׃
וּמוֹלַדְתְּךָ אֲשֶׁר־הוֹלַדְתָּ אַחֲרֵיהֶם לְךָ יִהְיוּ עַל שֵׁם אֲחֵיהֶם יִקָּרְאוּ בְּנַחֲלָתָם׃
וַאֲנִי בְּבֹאִי מִפַּדָּן מֵתָה עָלַי רָחֵל בְּאֶרֶץ כְּנַעַן בַּדֶּרֶךְ בְּעוֹד כִּבְרַת־אֶרֶץ לָבֹא אֶפְרָתָה וָאֶקְבְּרֶהָ שָּׁם בְּדֶרֶךְ אֶפְרָת הִוא בֵּית לָחֶם׃
וַיַּרְא יִשְׂרָאֵל אֶת־בְּנֵי יוֹסֵף וַיֹּאמֶר מִי־אֵלֶּה׃
וַיֹּאמֶר יוֹסֵף אֶל־אָבִיו בָּנַי הֵם אֲשֶׁר־נָתַן־לִי אֱלֹהִים בָּזֶה וַיֹּאמַר קָחֶם־נָא אֵלַי וַאֲבָרֲכֵם׃
וְעֵינֵי יִשְׂרָאֵל כָּבְדוּ מִזֹּקֶן לֹא יוּכַל לִרְאוֹת וַיַּגֵּשׁ אֹתָם אֵלָיו וַיִּשַּׁק לָהֶם וַיְחַבֵּק לָהֶם׃
וַיֹּאמֶר יִשְׂרָאֵל אֶל־יוֹסֵף רְאֹה פָנֶיךָ לֹא פִלָּלְתִּי וְהִנֵּה הֶרְאָה אֹתִי אֱלֹהִים גַּם אֶת־זַרְעֶךָ׃
וַיּוֹצֵא יוֹסֵף אֹתָם מֵעִם בִּרְכָּיו וַיִּשְׁתַּחוּ לְאַפָּיו אָרְצָה׃
וַיִּקַּח יוֹסֵף אֶת־שְׁנֵיהֶם אֶת־אֶפְרַיִם בִּימִינוֹ מִשְּׂמֹאל יִשְׂרָאֵל וְאֶת־מְנַשֶּׁה בִשְׂמֹאלוֹ מִימִין יִשְׂרָאֵל וַיַּגֵּשׁ אֵלָיו׃
וַיִּשְׁלַח יִשְׂרָאֵל אֶת־יְמִינוֹ וַיָּשֶׁת עַל־רֹאשׁ אֶפְרַיִם וְהוּא הַצָּעִיר וְאֶת־שְׂמֹאלוֹ עַל־רֹאשׁ מְנַשֶּׁה שִׂכֵּל אֶת־יָדָיו כִּי מְנַשֶּׁה הַבְּכוֹר׃
וַיְבָרֶךְ אֶת־יוֹסֵף וַיֹּאמַר הָאֱלֹהִים אֲשֶׁר הִתְהַלְּכוּ אֲבֹתַי לְפָנָיו אַבְרָהָם וְיִצְחָק הָאֱלֹהִים הָרֹעֶה אֹתִי מֵעוֹדִי עַד־הַיּוֹם הַזֶּה׃
הַמַּלְאָךְ הַגֹּאֵל אֹתִי מִכָּל־רָע יְבָרֵךְ אֶת־הַנְּעָרִים וְיִקָּרֵא בָהֶם שְׁמִי וְשֵׁם אֲבֹתַי אַבְרָהָם וְיִצְחָק וְיִדְגּוּ לָרֹב בְּקֶרֶב הָאָרֶץ׃
וַיַּרְא יוֹסֵף כִּי־יָשִׁית אָבִיו יַד־יְמִינוֹ עַל־רֹאשׁ אֶפְרַיִם וַיֵּרַע בְּעֵינָיו וַיִּתְמֹךְ יַד־אָבִיו לְהָסִיר אֹתָהּ מֵעַל רֹאשׁ־אֶפְרַיִם עַל־רֹאשׁ מְנַשֶּׁה׃
וַיֹּאמֶר יוֹסֵף אֶל־אָבִיו לֹא־כֵן אָבִי כִּי־זֶה הַבְּכֹר שִׂים יְמִינְךָ עַל־רֹאשׁוֹ׃
וַיְמָאֵן אָבִיו וַיֹּאמֶר יָדַעְתִּי בְנִי יָדַעְתִּי גַּם־הוּא יִהְיֶה־לְּעָם וְגַם־הוּא יִגְדָּל וְאוּלָם אָחִיו הַקָּטֹן יִגְדַּל מִמֶּנּוּ וְזַרְעוֹ יִהְיֶה מְלֹא־הַגּוֹיִם׃
וַיְבָרֲכֵם בַּיּוֹם הַהוּא לֵאמוֹר בְּךָ יְבָרֵךְ יִשְׂרָאֵל לֵאמֹר יְשִׂמְךָ אֱלֹהִים כְּאֶפְרַיִם וְכִמְנַשֶּׁה וַיָּשֶׂם אֶת־אֶפְרַיִם לִפְנֵי מְנַשֶּׁה׃
וַיֹּאמֶר יִשְׂרָאֵל אֶל־יוֹסֵף הִנֵּה אָנֹכִי מֵת וְהָיָה אֱלֹהִים עִמָּכֶם וְהֵשִׁיב אֶתְכֶם אֶל־אֶרֶץ אֲבֹתֵיכֶם׃
וַאֲנִי נָתַתִּי לְךָ שְׁכֶם אַחַד עַל־אַחֶיךָ אֲשֶׁר לָקַחְתִּי מִיַּד הָאֱמֹרִי בְּחַרְבִּי וּבְקַשְׁתִּי׃

Chapter 49

וַיִּקְרָא יַעֲקֹב אֶל־בָּנָיו וַיֹּאמֶר הֵאָסְפוּ וְאַגִּידָה לָכֶם אֵת אֲשֶׁר־יִקְרָא אֶתְכֶם בְּאַחֲרִית הַיָּמִים׃
הִקָּבְצוּ וְשִׁמְעוּ בְּנֵי יַעֲקֹב וְשִׁמְעוּ אֶל־יִשְׂרָאֵל אֲבִיכֶם׃
רְאוּבֵן בְּכֹרִי אַתָּה כֹּחִי וְרֵאשִׁית אוֹנִי יֶתֶר שְׂאֵת וְיֶתֶר עָז׃
פַּחַז כַּמַּיִם אַל־תּוֹתַר כִּי עָלִיתָ מִשְׁכְּבֵי אָבִיךָ אָז חִלַּלְתָּ יְצוּעִי עָלָה׃
שִׁמְעוֹן וְלֵוִי אַחִים כְּלֵי חָמָס מְכֵרֹתֵיהֶם׃
בְּסֹדָם אַל־תָּבֹא נַפְשִׁי בִּקְהָלָם אַל־תֵּחַד כְּבֹדִי כִּי בְאַפָּם הָרְגוּ אִישׁ וּבִרְצֹנָם עִקְּרוּ־שׁוֹר׃
אָרוּר אַפָּם כִּי עָז וְעֶבְרָתָם כִּי קָשָׁתָה אֲחַלְּקֵם בְּיַעֲקֹב וַאֲפִיצֵם בְּיִשְׂרָאֵל׃
יְהוּדָה אַתָּה יוֹדוּךָ אַחֶיךָ יָדְךָ בְּעֹרֶף אֹיְבֶיךָ יִשְׁתַּחֲוּוּ לְךָ בְּנֵי אָבִיךָ׃
גּוּר אַרְיֵה יְהוּדָה מִטֶּרֶף בְּנִי עָלִיתָ כָּרַע רָבַץ כְּאַרְיֵה וּכְלָבִיא מִי יְקִימֶנּוּ׃
לֹא־יָסוּר שֵׁבֶט מִיהוּדָה וּמְחֹקֵק מִבֵּין רַגְלָיו עַד כִּי־יָבֹא שילה [שִׁילוֹ] וְלוֹ יִקְּהַת עַמִּים׃
אֹסְרִי לַגֶּפֶן עירה [עִירוֹ] וְלַשֹּׂרֵקָה בְּנִי אֲתֹנוֹ כִּבֵּס בַּיַּיִן לְבֻשׁוֹ וּבְדַם־עֲנָבִים סותה [סוּתוֹ׃]
חַכְלִילִי עֵינַיִם מִיָּיִן וּלְבֶן־שִׁנַּיִם מֵחָלָב׃
זְבוּלֻן לְחוֹף יַמִּים יִשְׁכֹּן וְהוּא לְחוֹף אֳנִיּוֹת וְיַרְכָתוֹ עַל־צִידֹן׃
יִשָּׂשכָר חֲמֹר גָּרֶם רֹבֵץ בֵּין הַמִּשְׁפְּתָיִם׃
וַיַּרְא מְנֻחָה כִּי טוֹב וְאֶת־הָאָרֶץ כִּי נָעֵמָה וַיֵּט שִׁכְמוֹ לִסְבֹּל וַיְהִי לְמַס־עֹבֵד׃
דָּן יָדִין עַמּוֹ כְּאַחַד שִׁבְטֵי יִשְׂרָאֵל׃
יְהִי־דָן נָחָשׁ עֲלֵי־דֶרֶךְ שְׁפִיפֹן עֲלֵי־אֹרַח הַנֹּשֵׁךְ עִקְּבֵי־סוּס וַיִּפֹּל רֹכְבוֹ אָחוֹר׃
לִישׁוּעָתְךָ קִוִּיתִי יְהוָה׃
גָּד גְּדוּד יְגוּדֶנּוּ וְהוּא יָגֻד עָקֵב׃
מֵאָשֵׁר שְׁמֵנָה לַחְמוֹ וְהוּא יִתֵּן מַעֲדַנֵּי־מֶלֶךְ׃
נַפְתָּלִי אַיָּלָה שְׁלֻחָה הַנֹּתֵן אִמְרֵי־שָׁפֶר׃
בֵּן פֹּרָת יוֹסֵף בֵּן פֹּרָת עֲלֵי־עָיִן בָּנוֹת צָעֲדָה עֲלֵי־שׁוּר׃
וַיְמָרֲרֻהוּ וָרֹבּוּ וַיִּשְׂטְמֻהוּ בַּעֲלֵי חִצִּים׃
וַתֵּשֶׁב בְּאֵיתָן קַשְׁתּוֹ וַיָּפֹזּוּ זְרֹעֵי יָדָיו מִידֵי אֲבִיר יַעֲקֹב מִשָּׁם רֹעֶה אֶבֶן יִשְׂרָאֵל׃
מֵאֵל אָבִיךָ וְיַעְזְרֶךָּ וְאֵת שַׁדַּי וִיבָרְכֶךָּ בִּרְכֹת שָׁמַיִם מֵעָל בִּרְכֹת תְּהוֹם רֹבֶצֶת תָּחַת בִּרְכֹת שָׁדַיִם וָרָחַם׃
בִּרְכֹת אָבִיךָ גָּבְרוּ עַל־בִּרְכֹת הוֹרַי עַד־תַּאֲוַת גִּבְעֹת עוֹלָם תִּהְיֶין לְרֹאשׁ יוֹסֵף וּלְקָדְקֹד נְזִיר אֶחָיו׃
בִּנְיָמִין זְאֵב יִטְרָף בַּבֹּקֶר יֹאכַל עַד וְלָעֶרֶב יְחַלֵּק שָׁלָל׃
כָּל־אֵלֶּה שִׁבְטֵי יִשְׂרָאֵל שְׁנֵים עָשָׂר וְזֹאת אֲשֶׁר־דִּבֶּר לָהֶם אֲבִיהֶם וַיְבָרֶךְ אוֹתָם אִישׁ אֲשֶׁר כְּבִרְכָתוֹ בֵּרַךְ אֹתָם׃
וַיְצַו אוֹתָם וַיֹּאמֶר אֲלֵהֶם אֲנִי נֶאֱסָף אֶל־עַמִּי קִבְרוּ אֹתִי אֶל־אֲבֹתָי אֶל־הַמְּעָרָה אֲשֶׁר בִּשְׂדֵה עֶפְרוֹן הַחִתִּי׃
בַּמְּעָרָה אֲשֶׁר בִּשְׂדֵה הַמַּכְפֵּלָה אֲשֶׁר עַל־פְּנֵי־מַמְרֵא בְּאֶרֶץ כְּנָעַן אֲשֶׁר קָנָה אַבְרָהָם אֶת־הַשָּׂדֶה מֵאֵת עֶפְרֹן הַחִתִּי לַאֲחֻזַּת־קָבֶר׃
שָׁמָּה קָבְרוּ אֶת־אַבְרָהָם וְאֵת שָׂרָה אִשְׁתּוֹ שָׁמָּה קָבְרוּ אֶת־יִצְחָק וְאֵת רִבְקָה אִשְׁתּוֹ וְשָׁמָּה קָבַרְתִּי אֶת־לֵאָה׃
מִקְנֵה הַשָּׂדֶה וְהַמְּעָרָה אֲשֶׁר־בּוֹ מֵאֵת בְּנֵי־חֵת׃
וַיְכַל יַעֲקֹב לְצַוֺּת אֶת־בָּנָיו וַיֶּאֱסֹף רַגְלָיו אֶל־הַמִּטָּה וַיִּגְוַע וַיֵּאָסֶף אֶל־עַמָּיו׃

Chapter 50

וַיִּפֹּל יוֹסֵף עַל־פְּנֵי אָבִיו וַיֵּבְךְּ עָלָיו וַיִּשַּׁק־לוֹ׃
וַיְצַו יוֹסֵף אֶת־עֲבָדָיו אֶת־הָרֹפְאִים לַחֲנֹט אֶת־אָבִיו וַיַּחַנְטוּ הָרֹפְאִים אֶת־יִשְׂרָאֵל׃
וַיִּמְלְאוּ־לוֹ אַרְבָּעִים יוֹם כִּי כֵּן יִמְלְאוּ יְמֵי הַחֲנֻטִים וַיִּבְכּוּ אֹתוֹ מִצְרַיִם שִׁבְעִים יוֹם׃
וַיַּעַבְרוּ יְמֵי בְכִיתוֹ וַיְדַבֵּר יוֹסֵף אֶל־בֵּית פַּרְעֹה לֵאמֹר אִם־נָא מָצָאתִי חֵן בְּעֵינֵיכֶם דַּבְּרוּ־נָא בְּאָזְנֵי פַרְעֹה לֵאמֹר׃
אָבִי הִשְׁבִּיעַנִי לֵאמֹר הִנֵּה אָנֹכִי מֵת בְּקִבְרִי אֲשֶׁר כָּרִיתִי לִי בְּאֶרֶץ כְּנַעַן שָׁמָּה תִּקְבְּרֵנִי וְעַתָּה אֶעֱלֶה־נָּא וְאֶקְבְּרָה אֶת־אָבִי וְאָשׁוּבָה׃
וַיֹּאמֶר פַּרְעֹה עֲלֵה וּקְבֹר אֶת־אָבִיךָ כַּאֲשֶׁר הִשְׁבִּיעֶךָ׃
וַיַּעַל יוֹסֵף לִקְבֹּר אֶת־אָבִיו וַיַּעֲלוּ אִתּוֹ כָּל־עַבְדֵי פַרְעֹה זִקְנֵי בֵיתוֹ וְכֹל זִקְנֵי אֶרֶץ־מִצְרָיִם׃
וְכֹל בֵּית יוֹסֵף וְאֶחָיו וּבֵית אָבִיו רַק טַפָּם וְצֹאנָם וּבְקָרָם עָזְבוּ בְּאֶרֶץ גֹּשֶׁן׃
וַיַּעַל עִמּוֹ גַּם־רֶכֶב גַּם־פָּרָשִׁים וַיְהִי הַמַּחֲנֶה כָּבֵד מְאֹד׃
וַיָּבֹאוּ עַד־גֹּרֶן הָאָטָד אֲשֶׁר בְּעֵבֶר הַיַּרְדֵּן וַיִּסְפְּדוּ־שָׁם מִסְפֵּד גָּדוֹל וְכָבֵד מְאֹד וַיַּעַשׂ לְאָבִיו אֵבֶל שִׁבְעַת יָמִים׃
וַיַּרְא יוֹשֵׁב הָאָרֶץ הַכְּנַעֲנִי אֶת־הָאֵבֶל בְּגֹרֶן הָאָטָד וַיֹּאמְרוּ אֵבֶל־כָּבֵד זֶה לְמִצְרָיִם עַל־כֵּן קָרָא שְׁמָהּ אָבֵל מִצְרַיִם אֲשֶׁר בְּעֵבֶר הַיַּרְדֵּן׃
וַיַּעֲשׂוּ בָנָיו לוֹ כֵּן כַּאֲשֶׁר צִוָּם׃
וַיִּשְׂאוּ אֹתוֹ בָנָיו אַרְצָה כְּנַעַן וַיִּקְבְּרוּ אֹתוֹ בִּמְעָרַת שְׂדֵה הַמַּכְפֵּלָה אֲשֶׁר קָנָה אַבְרָהָם אֶת־הַשָּׂדֶה לַאֲחֻזַּת־קֶבֶר מֵאֵת עֶפְרֹן הַחִתִּי עַל־פְּנֵי מַמְרֵא׃
וַיָּשָׁב יוֹסֵף מִצְרַיְמָה הוּא וְאֶחָיו וְכָל־הָעֹלִים אִתּוֹ לִקְבֹּר אֶת־אָבִיו אַחֲרֵי קָבְרוֹ אֶת־אָבִיו׃
וַיִּרְאוּ אֲחֵי־יוֹסֵף כִּי־מֵת אֲבִיהֶם וַיֹּאמְרוּ לוּ יִשְׂטְמֵנוּ יוֹסֵף וְהָשֵׁב יָשִׁיב לָנוּ אֵת כָּל־הָרָעָה אֲשֶׁר גָּמַלְנוּ אֹתוֹ׃
וַיְצַוּוּ אֶל־יוֹסֵף לֵאמֹר אָבִיךָ צִוָּה לִפְנֵי מוֹתוֹ לֵאמֹר׃
כֹּה־תֹאמְרוּ לְיוֹסֵף אָנָּא שָׂא נָא פֶּשַׁע אַחֶיךָ וְחַטָּאתָם כִּי־רָעָה גְמָלוּךָ וְעַתָּה שָׂא נָא לְפֶשַׁע עַבְדֵי אֱלֹהֵי אָבִיךָ וַיֵּבְךְּ יוֹסֵף בְּדַבְּרָם אֵלָיו׃
וַיֵּלְכוּ גַּם־אֶחָיו וַיִּפְּלוּ לְפָנָיו וַיֹּאמְרוּ הִנֶּנּוּ לְךָ לַעֲבָדִים׃
וַיֹּאמֶר אֲלֵהֶם יוֹסֵף אַל־תִּירָאוּ כִּי הֲתַחַת אֱלֹהִים אָנִי׃
וְאַתֶּם חֲשַׁבְתֶּם עָלַי רָעָה אֱלֹהִים חֲשָׁבָהּ לְטֹבָה לְמַעַן עֲשֹׂה כַּיּוֹם הַזֶּה לְהַחֲיֹת עַם־רָב׃
וְעַתָּה אַל־תִּירָאוּ אָנֹכִי אֲכַלְכֵּל אֶתְכֶם וְאֶת־טַפְּכֶם וַיְנַחֵם אוֹתָם וַיְדַבֵּר עַל־לִבָּם׃
וַיֵּשֶׁב יוֹסֵף בְּמִצְרַיִם הוּא וּבֵית אָבִיו וַיְחִי יוֹסֵף מֵאָה וָעֶשֶׂר שָׁנִים׃
וַיַּרְא יוֹסֵף לְאֶפְרַיִם בְּנֵי שִׁלֵּשִׁים גַּם בְּנֵי מָכִיר בֶּן־מְנַשֶּׁה יֻלְּדוּ עַל־בִּרְכֵּי יוֹסֵף׃
וַיֹּאמֶר יוֹסֵף אֶל־אֶחָיו אָנֹכִי מֵת וֵאלֹהִים פָּקֹד יִפְקֹד אֶתְכֶם וְהֶעֱלָה אֶתְכֶם מִן־הָאָרֶץ הַזֹּאת אֶל־הָאָרֶץ אֲשֶׁר נִשְׁבַּע לְאַבְרָהָם לְיִצְחָק וּלְיַעֲקֹב׃
וַיַּשְׁבַּע יוֹסֵף אֶת־בְּנֵי יִשְׂרָאֵל לֵאמֹר פָּקֹד יִפְקֹד אֱלֹהִים אֶתְכֶם וְהַעֲלִתֶם אֶת־עַצְמֹתַי מִזֶּה׃
וַיָּמָת יוֹסֵף בֶּן־מֵאָה וָעֶשֶׂר שָׁנִים וַיַּחַנְטוּ אֹתוֹ וַיִּישֶׂם בָּאָרוֹן בְּמִצְרָיִם׃

============================================================
### Exodus  (/)
============================================================

Exodus
שמות
Tanach with Nikkud
http://www.tanach.us/Tanach.xml

שמות



Chapter 1

וְאֵלֶּה שְׁמוֹת בְּנֵי יִשְׂרָאֵל הַבָּאִים מִצְרָיְמָה אֵת יַעֲקֹב אִישׁ וּבֵיתוֹ בָּאוּ׃
רְאוּבֵן שִׁמְעוֹן לֵוִי וִיהוּדָה׃
יִשָּׂשכָר זְבוּלֻן וּבְנְיָמִן׃
דָּן וְנַפְתָּלִי גָּד וְאָשֵׁר׃
וַיְהִי כָּל־נֶפֶשׁ יֹצְאֵי יֶרֶךְ־יַעֲקֹב שִׁבְעִים נָפֶשׁ וְיוֹסֵף הָיָה בְמִצְרָיִם׃
וַיָּמָת יוֹסֵף וְכָל־אֶחָיו וְכֹל הַדּוֹר הַהוּא׃
וּבְנֵי יִשְׂרָאֵל פָּרוּ וַיִּשְׁרְצוּ וַיִּרְבּוּ וַיַּעַצְמוּ בִּמְאֹד מְאֹד וַתִּמָּלֵא הָאָרֶץ אֹתָם׃
וַיָּקָם מֶלֶךְ־חָדָשׁ עַל־מִצְרָיִם אֲשֶׁר לֹא־יָדַע אֶת־יוֹסֵף׃
וַיֹּאמֶר אֶל־עַמּוֹ הִנֵּה עַם בְּנֵי יִשְׂרָאֵל רַב וְעָצוּם מִמֶּנּוּ׃
הָבָה נִתְחַכְּמָה לוֹ פֶּן־יִרְבֶּה וְהָיָה כִּי־תִקְרֶאנָה מִלְחָמָה וְנוֹסַף גַּם־הוּא עַל־שֹׂנְאֵינוּ וְנִלְחַם־בָּנוּ וְעָלָה מִן־הָאָרֶץ׃
וַיָּשִׂימוּ עָלָיו שָׂרֵי מִסִּים לְמַעַן עַנֹּתוֹ בְּסִבְלֹתָם וַיִּבֶן עָרֵי מִסְכְּנוֹת לְפַרְעֹה אֶת־פִּתֹם וְאֶת־רַעַמְסֵס׃
וְכַאֲשֶׁר יְעַנּוּ אֹתוֹ כֵּן יִרְבֶּה וְכֵן יִפְרֹץ וַיָּקֻצוּ מִפְּנֵי בְּנֵי יִשְׂרָאֵל׃
וַיַּעֲבִדוּ מִצְרַיִם אֶת־בְּנֵי יִשְׂרָאֵל בְּפָרֶךְ׃
וַיְמָרְרוּ אֶת־חַיֵּיהֶם בַּעֲבֹדָה קָשָׁה בְּחֹמֶר וּבִלְבֵנִים וּבְכָל־עֲבֹדָה בַּשָּׂדֶה אֵת כָּל־עֲבֹדָתָם אֲשֶׁר־עָבְדוּ בָהֶם בְּפָרֶךְ׃
וַיֹּאמֶר מֶלֶךְ מִצְרַיִם לַמְיַלְּדֹת הָעִבְרִיֹּת אֲשֶׁר שֵׁם הָאַחַת שִׁפְרָה וְשֵׁם הַשֵּׁנִית פּוּעָה׃
וַיֹּאמֶר בְּיַלֶּדְכֶן אֶת־הָעִבְרִיּוֹת וּרְאִיתֶן עַל־הָאָבְנָיִם אִם־בֵּן הוּא וַהֲמִתֶּן אֹתוֹ וְאִם־בַּת הִיא וָחָיָה׃
וַתִּירֶאןָ הַמְיַלְּדֹת אֶת־הָאֱלֹהִים וְלֹא עָשׂוּ כַּאֲשֶׁר דִּבֶּר אֲלֵיהֶן מֶלֶךְ מִצְרָיִם וַתְּחַיֶּיןָ אֶת־הַיְלָדִים׃
וַיִּקְרָא מֶלֶךְ־מִצְרַיִם לַמְיַלְּדֹת וַיֹּאמֶר לָהֶן מַדּוּעַ עֲשִׂיתֶן הַדָּבָר הַזֶּה וַתְּחַיֶּיןָ אֶת־הַיְלָדִים׃
וַתֹּאמַרְןָ הַמְיַלְּדֹת אֶל־פַּרְעֹה כִּי לֹא כַנָּשִׁים הַמִּצְרִיֹּת הָעִבְרִיֹּת כִּי־חָיוֹת הֵנָּה בְּטֶרֶם תָּבוֹא אֲלֵהֶן הַמְיַלֶּדֶת וְיָלָדוּ׃
וַיֵּיטֶב אֱלֹהִים לַמְיַלְּדֹת וַיִּרֶב הָעָם וַיַּעַצְמוּ מְאֹד׃
וַיְהִי כִּי־יָרְאוּ הַמְיַלְּדֹת אֶת־הָאֱלֹהִים וַיַּעַשׂ לָהֶם בָּתִּים׃
וַיְצַו פַּרְעֹה לְכָל־עַמּוֹ לֵאמֹר כָּל־הַבֵּן הַיִּלּוֹד הַיְאֹרָה תַּשְׁלִיכֻהוּ וְכָל־הַבַּת תְּחַיּוּן׃

Chapter 2

וַיֵּלֶךְ אִישׁ מִבֵּית לֵוִי וַיִּקַּח אֶת־בַּת־לֵוִי׃
וַתַּהַר הָאִשָּׁה וַתֵּלֶד בֵּן וַתֵּרֶא אֹתוֹ כִּי־טוֹב הוּא וַתִּצְפְּנֵהוּ שְׁלֹשָׁה יְרָחִים׃
וְלֹא־יָכְלָה עוֹד הַצְּפִינוֹ וַתִּקַּח־לוֹ תֵּבַת גֹּמֶא וַתַּחְמְרָה בַחֵמָר וּבַזָּפֶת וַתָּשֶׂם בָּהּ אֶת־הַיֶּלֶד וַתָּשֶׂם בַּסּוּף עַל־שְׂפַת הַיְאֹר׃
וַתֵּתַצַּב אֲחֹתוֹ מֵרָחֹק לְדֵעָה מַה־יֵּעָשֶׂה לוֹ׃
וַתֵּרֶד בַּת־פַּרְעֹה לִרְחֹץ עַל־הַיְאֹר וְנַעֲרֹתֶיהָ הֹלְכֹת עַל־יַד הַיְאֹר וַתֵּרֶא אֶת־הַתֵּבָה בְּתוֹךְ הַסּוּף וַתִּשְׁלַח אֶת־אֲמָתָהּ וַתִּקָּחֶהָ
וַתִּפְתַּח וַתִּרְאֵהוּ אֶת־הַיֶּלֶד וְהִנֵּה־נַעַר בֹּכֶה וַתַּחְמֹל עָלָיו וַתֹּאמֶר מִיַּלְדֵי הָעִבְרִים זֶה׃
וַתֹּאמֶר אֲחֹתוֹ אֶל־בַּת־פַּרְעֹה הַאֵלֵךְ וְקָרָאתִי לָךְ אִשָּׁה מֵינֶקֶת מִן הָעִבְרִיֹּת וְתֵינִק לָךְ אֶת־הַיָּלֶד׃
וַתֹּאמֶר־לָהּ בַּת־פַּרְעֹה לֵכִי וַתֵּלֶךְ הָעַלְמָה וַתִּקְרָא אֶת־אֵם הַיָּלֶד׃
וַתֹּאמֶר לָהּ בַּת־פַּרְעֹה הֵילִיכִי אֶת־הַיֶּלֶד הַזֶּה וְהֵינִקִהוּ לִי וַאֲנִי אֶתֵּן אֶת־שְׂכָרֵךְ וַתִּקַּח הָאִשָּׁה הַיֶּלֶד וַתְּנִיקֵהוּ׃
וַיִגְדַּל הַיֶּלֶד וַתְּבִאֵהוּ לְבַת־פַּרְעֹה וַיְהִי־לָהּ לְבֵן וַתִּקְרָא שְׁמוֹ מֹשֶׁה וַתֹּאמֶר כִּי מִן־הַמַּיִם מְשִׁיתִהוּ׃
וַיְהִי בַּיָּמִים הָהֵם וַיִּגְדַּל מֹשֶׁה וַיֵּצֵא אֶל־אֶחָיו וַיַּרְא בְּסִבְלֹתָם וַיַּרְא אִישׁ מִצְרִי מַכֶּה אִישׁ־עִבְרִי מֵאֶחָיו׃
וַיִּפֶן כֹּה וָכֹה וַיַּרְא כִּי אֵין אִישׁ וַיַּךְ אֶת־הַמִּצְרִי וַיִּטְמְנֵהוּ בַּחוֹל׃
וַיֵּצֵא בַּיּוֹם הַשֵּׁנִי וְהִנֵּה שְׁנֵי־אֲנָשִׁים עִבְרִים נִצִּים וַיֹּאמֶר לָרָשָׁע לָמָּה תַכֶּה רֵעֶךָ׃
וַיֹּאמֶר מִי שָׂמְךָ לְאִישׁ שַׂר וְשֹׁפֵט עָלֵינוּ הַלְהָרְגֵנִי אַתָּה אֹמֵר כַּאֲשֶׁר הָרַגְתָּ אֶת־הַמִּצְרִי וַיִּירָא מֹשֶׁה וַיֹּאמַר אָכֵן נוֹדַע הַדָּבָר׃
וַיִּשְׁמַע פַּרְעֹה אֶת־הַדָּבָר הַזֶּה וַיְבַקֵּשׁ לַהֲרֹג אֶת־מֹשֶׁה וַיִּבְרַח מֹשֶׁה מִפְּנֵי פַרְעֹה וַיֵּשֶׁב בְּאֶרֶץ־מִדְיָן וַיֵּשֶׁב עַל־הַבְּאֵר׃
וּלְכֹהֵן מִדְיָן שֶׁבַע בָּנוֹת וַתָּבֹאנָה וַתִּדְלֶנָה וַתְּמַלֶּאנָה אֶת־הָרְהָטִים לְהַשְׁקוֹת צֹאן אֲבִיהֶן׃
וַיָּבֹאוּ הָרֹעִים וַיְגָרְשׁוּם וַיָּקָם מֹשֶׁה וַיּוֹשִׁעָן וַיַּשְׁקְ אֶת־צֹאנָם׃
וַתָּבֹאנָה אֶל־רְעוּאֵל אֲבִיהֶן וַיֹּאמֶר מַדּוּעַ מִהַרְתֶּן בֹּא הַיּוֹם׃
וַתֹּאמַרְןָ אִישׁ מִצְרִי הִצִּילָנוּ מִיַּד הָרֹעִים וְגַם־דָּלֹה דָלָה לָנוּ וַיַּשְׁקְ אֶת־הַצֹּאן׃
וַיֹּאמֶר אֶל־בְּנֹתָיו וְאַיּוֹ לָמָּה זֶּה עֲזַבְתֶּן אֶת־הָאִישׁ קִרְאֶן לוֹ וְיֹאכַל לָחֶם׃
וַיּוֹאֶל מֹשֶׁה לָשֶׁבֶת אֶת־הָאִישׁ וַיִּתֵּן אֶת־צִפֹּרָה בִתּוֹ לְמֹשֶׁה׃
וַתֵּלֶד בֵּן וַיִּקְרָא אֶת־שְׁמוֹ גֵּרְשֹׁם כִּי אָמַר גֵּר הָיִיתִי בְּאֶרֶץ נָכְרִיָּה׃
וַיְהִי בַיָּמִים הָרַבִּים הָהֵם וַיָּמָת מֶלֶךְ מִצְרַיִם וַיֵּאָנְחוּ בְנֵי־יִשְׂרָאֵל מִן־הָעֲבֹדָה וַיִּזְעָקוּ וַתַּעַל שַׁוְעָתָם אֶל־הָאֱלֹהִים מִן־הָעֲבֹדָה׃
וַיִּשְׁמַע אֱלֹהִים אֶת־נַאֲקָתָם וַיִּזְכֹּר אֱלֹהִים אֶת־בְּרִיתוֹ אֶת־אַבְרָהָם אֶת־יִצְחָק וְאֶת־יַעֲקֹב׃
וַיַּרְא אֱלֹהִים אֶת־בְּנֵי יִשְׂרָאֵל וַיֵּדַע אֱלֹהִים׃

Chapter 3

וּמֹשֶׁה הָיָה רֹעֶה אֶת־צֹאן יִתְרוֹ חֹתְנוֹ כֹּהֵן מִדְיָן וַיִּנְהַג אֶת־הַצֹּאן אַחַר הַמִּדְבָּר וַיָּבֹא אֶל־הַר הָאֱלֹהִים חֹרֵבָה׃
וַיֵּרָא מַלְאַךְ יְהֹוָה אֵלָיו בְּלַבַּת־אֵשׁ מִתּוֹךְ הַסְּנֶה וַיַּרְא וְהִנֵּה הַסְּנֶה בֹּעֵר בָּאֵשׁ וְהַסְּנֶה אֵינֶנּוּ אֻכָּל׃
וַיֹּאמֶר מֹשֶׁה אָסֻרָה־נָּא וְאֶרְאֶה אֶת־הַמַּרְאֶה הַגָּדֹל הַזֶּה מַדּוּעַ לֹא־יִבְעַר הַסְּנֶה׃
וַיַּרְא יְהוָה כִּי סָר לִרְאוֹת וַיִּקְרָא אֵלָיו אֱלֹהִים מִתּוֹךְ הַסְּנֶה וַיֹּאמֶר מֹשֶׁה מֹשֶׁה וַיֹּאמֶר הִנֵּנִי׃
וַיֹּאמֶר אַל־תִּקְרַב הֲלֹם שַׁל־נְעָלֶיךָ מֵעַל רַגְלֶיךָ כִּי הַמָּקוֹם אֲשֶׁר אַתָּה עוֹמֵד עָלָיו אַדְמַת־קֹדֶשׁ הוּא׃
וַיֹּאמֶר אָנֹכִי אֱלֹהֵי אָבִיךָ אֱלֹהֵי אַבְרָהָם אֱלֹהֵי יִצְחָק וֵאלֹהֵי יַעֲקֹב וַיַּסְתֵּר מֹשֶׁה פָּנָיו כִּי יָרֵא מֵהַבִּיט אֶל־הָאֱלֹהִים׃
וַיֹּאמֶר יְהוָה רָאֹה רָאִיתִי אֶת־עֳנִי עַמִּי אֲשֶׁר בְּמִצְרָיִם וְאֶת־צַעֲקָתָם שָׁמַעְתִּי מִפְּנֵי נֹגְשָׂיו כִּי יָדַעְתִּי אֶת־מַכְאֹבָיו׃
וָאֵרֵד לְהַצִּילוֹ מִיַּד מִצְרַיִם וּלְהַעֲלֹתוֹ מִן־הָאָרֶץ הַהִוא אֶל־אֶרֶץ טוֹבָה וּרְחָבָה אֶל־אֶרֶץ זָבַת חָלָב וּדְבָשׁ אֶל־מְקוֹם הַכְּנַעֲנִי וְהַחִתִּי וְהָאֱמֹרִי וְהַפְּרִזִּי וְהַחִוִּי וְהַיְבוּסִי׃
וְעַתָּה הִנֵּה צַעֲקַת בְּנֵי־יִשְׂרָאֵל בָּאָה אֵלָי וְגַם־רָאִיתִי אֶת־הַלַּחַץ אֲשֶׁר מִצְרַיִם לֹחֲצִים אֹתָם׃
וְעַתָּה לְכָה וְאֶשְׁלָחֲךָ אֶל־פַּרְעֹה וְהוֹצֵא אֶת־עַמִּי בְנֵי־יִשְׂרָאֵל מִמִּצְרָיִם׃
וַיֹּאמֶר מֹשֶׁה אֶל־הָאֱלֹהִים מִי אָנֹכִי כִּי אֵלֵךְ אֶל־פַּרְעֹה וְכִי אוֹצִיא אֶת־בְּנֵי יִשְׂרָאֵל מִמִּצְרָיִם׃
וַיֹּאמֶר כִּי־אֶהְיֶה עִמָּךְ וְזֶה־לְּךָ הָאוֹת כִּי אָנֹכִי שְׁלַחְתִּיךָ בְּהוֹצִיאֲךָ אֶת־הָעָם מִמִּצְרַיִם תַּעַבְדוּן אֶת־הָאֱלֹהִים עַל הָהָר הַזֶּה׃
וַיֹּאמֶר מֹשֶׁה אֶל־הָאֱלֹהִים הִנֵּה אָנֹכִי בָא אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתִּי לָהֶם אֱלֹהֵי אֲבוֹתֵיכֶם שְׁלָחַנִי אֲלֵיכֶם וְאָמְרוּ־לִי מַה־שְּׁמוֹ מָה אֹמַר אֲלֵהֶם׃
וַיֹּאמֶר אֱלֹהִים אֶל־מֹשֶׁה אֶהְיֶה אֲשֶׁר אֶהְיֶה וַיֹּאמֶר כֹּה תֹאמַר לִבְנֵי יִשְׂרָאֵל אֶהְיֶה שְׁלָחַנִי אֲלֵיכֶם׃
וַיֹּאמֶר עוֹד אֱלֹהִים אֶל־מֹשֶׁה כֹּה־תֹאמַר אֶל־בְּנֵי יִשְׂרָאֵל יְהוָה אֱלֹהֵי אֲבֹתֵיכֶם אֱלֹהֵי אַבְרָהָם אֱלֹהֵי יִצְחָק וֵאלֹהֵי יַעֲקֹב שְׁלָחַנִי אֲלֵיכֶם זֶה־שְּׁמִי לְעֹלָם וְזֶה זִכְרִי לְדֹר דֹּר׃
לֵךְ וְאָסַפְתָּ אֶת־זִקְנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם יְהוָה אֱלֹהֵי אֲבֹתֵיכֶם נִרְאָה אֵלַי אֱלֹהֵי אַבְרָהָם יִצְחָק וְיַעֲקֹב לֵאמֹר פָּקֹד פָּקַדְתִּי אֶתְכֶם וְאֶת־הֶעָשׂוּי לָכֶם בְּמִצְרָיִם׃
וָאֹמַר אַעֲלֶה אֶתְכֶם מֵעֳנִי מִצְרַיִם אֶל־אֶרֶץ הַכְּנַעֲנִי וְהַחִתִּי וְהָאֱמֹרִי וְהַפְּרִזִּי וְהַחִוִּי וְהַיְבוּסִי אֶל־אֶרֶץ זָבַת חָלָב וּדְבָשׁ׃
וְשָׁמְעוּ לְקֹלֶךָ וּבָאתָ אַתָּה וְזִקְנֵי יִשְׂרָאֵל אֶל־מֶלֶךְ מִצְרַיִם וַאֲמַרְתֶּם אֵלָיו יְהוָה אֱלֹהֵי הָעִבְרִיִּים נִקְרָה עָלֵינוּ וְעַתָּה נֵלֲכָה־נָּא דֶּרֶךְ שְׁלֹשֶׁת יָמִים בַּמִּדְבָּר וְנִזְבְּחָה לַיהוָה אֱלֹהֵינוּ׃
וַאֲנִי יָדַעְתִּי כִּי לֹא־יִתֵּן אֶתְכֶם מֶלֶךְ מִצְרַיִם לַהֲלֹךְ וְלֹא בְּיָד חֲזָקָה׃
וְשָׁלַחְתִּי אֶת־יָדִי וְהִכֵּיתִי אֶת־מִצְרַיִם בְּכֹל נִפְלְאֹתַי אֲשֶׁר אֶעֱשֶׂה בְּקִרְבּוֹ וְאַחֲרֵי־כֵן יְשַׁלַּח אֶתְכֶם׃
וְנָתַתִּי אֶת־חֵן הָעָם־הַזֶּה בְּעֵינֵי מִצְרָיִם וְהָיָה כִּי תֵלֵכוּן לֹא תֵלְכוּ רֵיקָם׃
וְשָׁאֲלָה אִשָּׁה מִשְּׁכֶנְתָּהּ וּמִגָּרַת בֵּיתָהּ כְּלֵי־כֶסֶף וּכְלֵי זָהָב וּשְׂמָלֹת וְשַׂמְתֶּם עַל־בְּנֵיכֶם וְעַל־בְּנֹתֵיכֶם וְנִצַּלְתֶּם אֶת־מִצְרָיִם׃

Chapter 4

וַיַּעַן מֹשֶׁה וַיֹּאמֶר וְהֵן לֹא־יַאֲמִינוּ לִי וְלֹא יִשְׁמְעוּ בְּקֹלִי כִּי יֹאמְרוּ לֹא־נִרְאָה אֵלֶיךָ יְהוָה׃
וַיֹּאמֶר אֵלָיו יְהוָה מזה [מַה־] [זֶּה] בְיָדֶךָ וַיֹּאמֶר מַטֶּה׃
וַיֹּאמֶר הַשְׁלִיכֵהוּ אַרְצָה וַיַּשְׁלִיכֵהוּ אַרְצָה וַיְהִי לְנָחָשׁ וַיָּנָס מֹשֶׁה מִפָּנָיו׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה שְׁלַח יָדְךָ וֶאֱחֹז בִּזְנָבוֹ וַיִּשְׁלַח יָדוֹ וַיַּחֲזֶק בּוֹ וַיְהִי לְמַטֶּה בְּכַפּוֹ׃
לְמַעַן יַאֲמִינוּ כִּי־נִרְאָה אֵלֶיךָ יְהוָה אֱלֹהֵי אֲבֹתָם אֱלֹהֵי אַבְרָהָם אֱלֹהֵי יִצְחָק וֵאלֹהֵי יַעֲקֹב׃
וַיֹּאמֶר יְהוָה לוֹ עוֹד הָבֵא־נָא יָדְךָ בְּחֵיקֶךָ וַיָּבֵא יָדוֹ בְּחֵיקוֹ וַיּוֹצִאָהּ וְהִנֵּה יָדוֹ מְצֹרַעַת כַּשָּׁלֶג׃
וַיֹּאמֶר הָשֵׁב יָדְךָ אֶל־חֵיקֶךָ וַיָּשֶׁב יָדוֹ אֶל־חֵיקוֹ וַיּוֹצִאָהּ מֵחֵיקוֹ וְהִנֵּה־שָׁבָה כִּבְשָׂרוֹ׃
וְהָיָה אִם־לֹא יַאֲמִינוּ לָךְ וְלֹא יִשְׁמְעוּ לְקֹל הָאֹת הָרִאשׁוֹן וְהֶאֱמִינוּ לְקֹל הָאֹת הָאַחֲרוֹן׃
וְהָיָה אִם־לֹא יַאֲמִינוּ גַּם לִשְׁנֵי הָאֹתוֹת הָאֵלֶּה וְלֹא יִשְׁמְעוּן לְקֹלֶךָ וְלָקַחְתָּ מִמֵּימֵי הַיְאֹר וְשָׁפַכְתָּ הַיַּבָּשָׁה וְהָיוּ הַמַּיִם אֲשֶׁר תִּקַּח מִן־הַיְאֹר וְהָיוּ לְדָם בַּיַּבָּשֶׁת׃
וַיֹּאמֶר מֹשֶׁה אֶל־יְהוָה בִּי אֲדֹנָי לֹא אִישׁ דְּבָרִים אָנֹכִי גַּם מִתְּמוֹל גַּם מִשִּׁלְשֹׁם גַּם מֵאָז דַּבֶּרְךָ אֶל־עַבְדֶּךָ כִּי כְבַד־פֶּה וּכְבַד לָשׁוֹן אָנֹכִי׃
וַיֹּאמֶר יְהוָה אֵלָיו מִי שָׂם פֶּה לָאָדָם אוֹ מִי־יָשׂוּם אִלֵּם אוֹ חֵרֵשׁ אוֹ פִקֵּחַ אוֹ עִוֵּר הֲלֹא אָנֹכִי יְהוָה׃
וְעַתָּה לֵךְ וְאָנֹכִי אֶהְיֶה עִם־פִּיךָ וְהוֹרֵיתִיךָ אֲשֶׁר תְּדַבֵּר׃
וַיֹּאמֶר בִּי אֲדֹנָי שְׁלַח־נָא בְּיַד־תִּשְׁלָח׃
וַיִּחַר־אַף יְהוָה בְּמֹשֶׁה וַיֹּאמֶר הֲלֹא אַהֲרֹן אָחִיךָ הַלֵּוִי יָדַעְתִּי כִּי־דַבֵּר יְדַבֵּר הוּא וְגַם הִנֵּה־הוּא יֹצֵא לִקְרָאתֶךָ וְרָאֲךָ וְשָׂמַח בְּלִבּוֹ׃
וְדִבַּרְתָּ אֵלָיו וְשַׂמְתָּ אֶת־הַדְּבָרִים בְּפִיו וְאָנֹכִי אֶהְיֶה עִם־פִּיךָ וְעִם־פִּיהוּ וְהוֹרֵיתִי אֶתְכֶם אֵת אֲשֶׁר תַּעֲשׂוּן׃
וְדִבֶּר־הוּא לְךָ אֶל־הָעָם וְהָיָה הוּא יִהְיֶה־לְּךָ לְפֶה וְאַתָּה תִּהְיֶה־לּוֹ לֵאלֹהִים׃
וְאֶת־הַמַּטֶּה הַזֶּה תִּקַּח בְּיָדֶךָ אֲשֶׁר תַּעֲשֶׂה־בּוֹ אֶת־הָאֹתֹת׃
וַיֵּלֶךְ מֹשֶׁה וַיָּשָׁב אֶל־יֶתֶר חֹתְנוֹ וַיֹּאמֶר לוֹ אֵלְכָה נָּא וְאָשׁוּבָה אֶל־אַחַי אֲשֶׁר־בְּמִצְרַיִם וְאֶרְאֶה הַעוֹדָם חַיִּים וַיֹּאמֶר יִתְרוֹ לְמֹשֶׁה לֵךְ לְשָׁלוֹם׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה בְּמִדְיָן לֵךְ שֻׁב מִצְרָיִם כִּי־מֵתוּ כָּל־הָאֲנָשִׁים הַמְבַקְשִׁים אֶת־נַפְשֶׁךָ׃
וַיִּקַּח מֹשֶׁה אֶת־אִשְׁתּוֹ וְאֶת־בָּנָיו וַיַּרְכִּבֵם עַל־הַחֲמֹר וַיָּשָׁב אַרְצָה מִצְרָיִם וַיִּקַּח מֹשֶׁה אֶת־מַטֵּה הָאֱלֹהִים בְּיָדוֹ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה בְּלֶכְתְּךָ לָשׁוּב מִצְרַיְמָה רְאֵה כָּל־הַמֹּפְתִים אֲשֶׁר־שַׂמְתִּי בְיָדֶךָ וַעֲשִׂיתָם לִפְנֵי פַרְעֹה וַאֲנִי אֲחַזֵּק אֶת־לִבּוֹ וְלֹא יְשַׁלַּח אֶת־הָעָם׃
וְאָמַרְתָּ אֶל־פַּרְעֹה כֹּה אָמַר יְהוָה בְּנִי בְכֹרִי יִשְׂרָאֵל׃
וָאֹמַר אֵלֶיךָ שַׁלַּח אֶת־בְּנִי וְיַעַבְדֵנִי וַתְּמָאֵן לְשַׁלְּחוֹ הִנֵּה אָנֹכִי הֹרֵג אֶת־בִּנְךָ בְּכֹרֶךָ׃
וַיְהִי בַדֶּרֶךְ בַּמָּלוֹן וַיִּפְגְּשֵׁהוּ יְהוָה וַיְבַקֵּשׁ הֲמִיתוֹ׃
וַתִּקַּח צִפֹּרָה צֹר וַתִּכְרֹת אֶת־עָרְלַת בְּנָהּ וַתַּגַּע לְרַגְלָיו וַתֹּאמֶר כִּי חֲתַן־דָּמִים אַתָּה לִי׃
וַיִּרֶף מִמֶּנּוּ אָז אָמְרָה חֲתַן דָּמִים לַמּוּלֹת׃
וַיֹּאמֶר יְהוָה אֶל־אַהֲרֹן לֵךְ לִקְרַאת מֹשֶׁה הַמִּדְבָּרָה וַיֵּלֶךְ וַיִּפְגְּשֵׁהוּ בְּהַר הָאֱלֹהִים וַיִּשַּׁק־לוֹ׃
וַיַּגֵּד מֹשֶׁה לְאַהֲרֹן אֵת כָּל־דִּבְרֵי יְהוָה אֲשֶׁר שְׁלָחוֹ וְאֵת כָּל־הָאֹתֹת אֲשֶׁר צִוָּהוּ׃
וַיֵּלֶךְ מֹשֶׁה וְאַהֲרֹן וַיַּאַסְפוּ אֶת־כָּל־זִקְנֵי בְּנֵי יִשְׂרָאֵל׃
וַיְדַבֵּר אַהֲרֹן אֵת כָּל־הַדְּבָרִים אֲשֶׁר־דִּבֶּר יְהוָה אֶל־מֹשֶׁה וַיַּעַשׂ הָאֹתֹת לְעֵינֵי הָעָם׃
וַיַּאֲמֵן הָעָם וַיִּשְׁמְעוּ כִּי־פָקַד יְהוָה אֶת־בְּנֵי יִשְׂרָאֵל וְכִי רָאָה אֶת־עָנְיָם וַיִּקְּדוּ וַיִּשְׁתַּחֲוּוּ׃

Chapter 5

וְאַחַר בָּאוּ מֹשֶׁה וְאַהֲרֹן וַיֹּאמְרוּ אֶל־פַּרְעֹה כֹּה־אָמַר יְהוָה אֱלֹהֵי יִשְׂרָאֵל שַׁלַּח אֶת־עַמִּי וְיָחֹגּוּ לִי בַּמִּדְבָּר׃
וַיֹּאמֶר פַּרְעֹה מִי יְהוָה אֲשֶׁר אֶשְׁמַע בְּקֹלוֹ לְשַׁלַּח אֶת־יִשְׂרָאֵל לֹא יָדַעְתִּי אֶת־יְהוָה וְגַם אֶת־יִשְׂרָאֵל לֹא אֲשַׁלֵּחַ׃
וַיֹּאמְרוּ אֱלֹהֵי הָעִבְרִים נִקְרָא עָלֵינוּ נֵלֲכָה נָּא דֶּרֶךְ שְׁלֹשֶׁת יָמִים בַּמִּדְבָּר וְנִזְבְּחָה לַיהוָה אֱלֹהֵינוּ פֶּן־יִפְגָּעֵנוּ בַּדֶּבֶר אוֹ בֶחָרֶב׃
וַיֹּאמֶר אֲלֵהֶם מֶלֶךְ מִצְרַיִם לָמָּה מֹשֶׁה וְאַהֲרֹן תַּפְרִיעוּ אֶת־הָעָם מִמַּעֲשָׂיו לְכוּ לְסִבְלֹתֵיכֶם׃
וַיֹּאמֶר פַּרְעֹה הֵן־רַבִּים עַתָּה עַם הָאָרֶץ וְהִשְׁבַּתֶּם אֹתָם מִסִּבְלֹתָם׃
וַיְצַו פַּרְעֹה בַּיּוֹם הַהוּא אֶת־הַנֹּגְשִׂים בָּעָם וְאֶת־שֹׁטְרָיו לֵאמֹר׃
לֹא תֹאסִפוּן לָתֵת תֶּבֶן לָעָם לִלְבֹּן הַלְּבֵנִים כִּתְמוֹל שִׁלְשֹׁם הֵם יֵלְכוּ וְקֹשְׁשׁוּ לָהֶם תֶּבֶן׃
וְאֶת־מַתְכֹּנֶת הַלְּבֵנִים אֲשֶׁר הֵם עֹשִׂים תְּמוֹל שִׁלְשֹׁם תָּשִׂימוּ עֲלֵיהֶם לֹא תִגְרְעוּ מִמֶּנּוּ כִּי־נִרְפִּים הֵם עַל־כֵּן הֵם צֹעֲקִים לֵאמֹר נֵלְכָה נִזְבְּחָה לֵאלֹהֵינוּ׃
תִּכְבַּד הָעֲבֹדָה עַל־הָאֲנָשִׁים וְיַעֲשׂוּ־בָהּ וְאַל־יִשְׁעוּ בְּדִבְרֵי־שָׁקֶר׃
וַיֵּצְאוּ נֹגְשֵׂי הָעָם וְשֹׁטְרָיו וַיֹּאמְרוּ אֶל־הָעָם לֵאמֹר כֹּה אָמַר פַּרְעֹה אֵינֶנִּי נֹתֵן לָכֶם תֶּבֶן׃
אַתֶּם לְכוּ קְחוּ לָכֶם תֶּבֶן מֵאֲשֶׁר תִּמְצָאוּ כִּי אֵין נִגְרָע מֵעֲבֹדַתְכֶם דָּבָר׃
וַיָּפֶץ הָעָם בְּכָל־אֶרֶץ מִצְרָיִם לְקֹשֵׁשׁ קַשׁ לַתֶּבֶן׃
וְהַנֹּגְשִׂים אָצִים לֵאמֹר כַּלּוּ מַעֲשֵׂיכֶם דְּבַר־יוֹם בְּיוֹמוֹ כַּאֲשֶׁר בִּהְיוֹת הַתֶּבֶן׃
וַיֻּכּוּ שֹׁטְרֵי בְּנֵי יִשְׂרָאֵל אֲשֶׁר־שָׂמוּ עֲלֵהֶם נֹגְשֵׂי פַרְעֹה לֵאמֹר מַדּוּעַ לֹא כִלִּיתֶם חָקְכֶם לִלְבֹּן כִּתְמוֹל שִׁלְשֹׁם גַּם־תְּמוֹל גַּם־הַיּוֹם׃
וַיָּבֹאוּ שֹׁטְרֵי בְּנֵי יִשְׂרָאֵל וַיִּצְעֲקוּ אֶל־פַּרְעֹה לֵאמֹר לָמָּה תַעֲשֶׂה כֹה לַעֲבָדֶיךָ׃
תֶּבֶן אֵין נִתָּן לַעֲבָדֶיךָ וּלְבֵנִים אֹמְרִים לָנוּ עֲשׂוּ וְהִנֵּה עֲבָדֶיךָ מֻכִּים וְחָטָאת עַמֶּךָ׃
וַיֹּאמֶר נִרְפִּים אַתֶּם נִרְפִּים עַל־כֵּן אַתֶּם אֹמְרִים נֵלְכָה נִזְבְּחָה לַיהוָה׃
וְעַתָּה לְכוּ עִבְדוּ וְתֶבֶן לֹא־יִנָּתֵן לָכֶם וְתֹכֶן לְבֵנִים תִּתֵּנּוּ׃
וַיִּרְאוּ שֹׁטְרֵי בְנֵי־יִשְׂרָאֵל אֹתָם בְּרָע לֵאמֹר לֹא־תִגְרְעוּ מִלִּבְנֵיכֶם דְּבַר־יוֹם בְּיוֹמוֹ׃
וַיִּפְגְּעוּ אֶת־מֹשֶׁה וְאֶת־אַהֲרֹן נִצָּבִים לִקְרָאתָם בְּצֵאתָם מֵאֵת פַּרְעֹה׃
וַיֹּאמְרוּ אֲלֵהֶם יֵרֶא יְהוָה עֲלֵיכֶם וְיִשְׁפֹּט אֲשֶׁר הִבְאַשְׁתֶּם אֶת־רֵיחֵנוּ בְּעֵינֵי פַרְעֹה וּבְעֵינֵי עֲבָדָיו לָתֶת־חֶרֶב בְּיָדָם לְהָרְגֵנוּ׃
וַיָּשָׁב מֹשֶׁה אֶל־יְהוָה וַיֹּאמַר אֲדֹנָי לָמָה הֲרֵעֹתָה לָעָם הַזֶּה לָמָּה זֶּה שְׁלַחְתָּנִי׃
וּמֵאָז בָּאתִי אֶל־פַּרְעֹה לְדַבֵּר בִּשְׁמֶךָ הֵרַע לָעָם הַזֶּה וְהַצֵּל לֹא־הִצַּלְתָּ אֶת־עַמֶּךָ׃

Chapter 6

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עַתָּה תִרְאֶה אֲשֶׁר אֶעֱשֶׂה לְפַרְעֹה כִּי בְיָד חֲזָקָה יְשַׁלְּחֵם וּבְיָד חֲזָקָה יְגָרְשֵׁם מֵאַרְצוֹ׃
וַיְדַבֵּר אֱלֹהִים אֶל־מֹשֶׁה וַיֹּאמֶר אֵלָיו אֲנִי יְהוָה׃
וָאֵרָא אֶל־אַבְרָהָם אֶל־יִצְחָק וְאֶל־יַעֲקֹב בְּאֵל שַׁדָּי וּשְׁמִי יְהוָה לֹא נוֹדַעְתִּי לָהֶם׃
וְגַם הֲקִמֹתִי אֶת־בְּרִיתִי אִתָּם לָתֵת לָהֶם אֶת־אֶרֶץ כְּנָעַן אֵת אֶרֶץ מְגֻרֵיהֶם אֲשֶׁר־גָּרוּ בָהּ׃
וְגַם אֲנִי שָׁמַעְתִּי אֶת־נַאֲקַת בְּנֵי יִשְׂרָאֵל אֲשֶׁר מִצְרַיִם מַעֲבִדִים אֹתָם וָאֶזְכֹּר אֶת־בְּרִיתִי׃
לָכֵן אֱמֹר לִבְנֵי־יִשְׂרָאֵל אֲנִי יְהוָה וְהוֹצֵאתִי אֶתְכֶם מִתַּחַת סִבְלֹת מִצְרַיִם וְהִצַּלְתִּי אֶתְכֶם מֵעֲבֹדָתָם וְגָאַלְתִּי אֶתְכֶם בִּזְרוֹעַ נְטוּיָה וּבִשְׁפָטִים גְּדֹלִים׃
וְלָקַחְתִּי אֶתְכֶם לִי לְעָם וְהָיִיתִי לָכֶם לֵאלֹהִים וִידַעְתֶּם כִּי אֲנִי יְהוָה אֱלֹהֵיכֶם הַמּוֹצִיא אֶתְכֶם מִתַּחַת סִבְלוֹת מִצְרָיִם׃
וְהֵבֵאתִי אֶתְכֶם אֶל־הָאָרֶץ אֲשֶׁר נָשָׂאתִי אֶת־יָדִי לָתֵת אֹתָהּ לְאַבְרָהָם לְיִצְחָק וּלְיַעֲקֹב וְנָתַתִּי אֹתָהּ לָכֶם מוֹרָשָׁה אֲנִי יְהוָה׃
וַיְדַבֵּר מֹשֶׁה כֵּן אֶל־בְּנֵי יִשְׂרָאֵל וְלֹא שָׁמְעוּ אֶל־מֹשֶׁה מִקֹּצֶר רוּחַ וּמֵעֲבֹדָה קָשָׁה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
בֹּא דַבֵּר אֶל־פַּרְעֹה מֶלֶךְ מִצְרָיִם וִישַׁלַּח אֶת־בְּנֵי־יִשְׂרָאֵל מֵאַרְצוֹ׃
וַיְדַבֵּר מֹשֶׁה לִפְנֵי יְהוָה לֵאמֹר הֵן בְּנֵי־יִשְׂרָאֵל לֹא־שָׁמְעוּ אֵלַי וְאֵיךְ יִשְׁמָעֵנִי פַרְעֹה וַאֲנִי עֲרַל שְׂפָתָיִם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן וַיְצַוֵּם אֶל־בְּנֵי יִשְׂרָאֵל וְאֶל־פַּרְעֹה מֶלֶךְ מִצְרָיִם לְהוֹצִיא אֶת־בְּנֵי־יִשְׂרָאֵל מֵאֶרֶץ מִצְרָיִם׃
אֵלֶּה רָאשֵׁי בֵית־אֲבֹתָם בְּנֵי רְאוּבֵן בְּכֹר יִשְׂרָאֵל חֲנוֹךְ וּפַלּוּא חֶצְרוֹן וְכַרְמִי אֵלֶּה מִשְׁפְּחֹת רְאוּבֵן׃
וּבְנֵי שִׁמְעוֹן יְמוּאֵל וְיָמִין וְאֹהַד וְיָכִין וְצֹחַר וְשָׁאוּל בֶּן־הַכְּנַעֲנִית אֵלֶּה מִשְׁפְּחֹת שִׁמְעוֹן׃
וְאֵלֶּה שְׁמוֹת בְּנֵי־לֵוִי לְתֹלְדֹתָם גֵּרְשׁוֹן וּקְהָת וּמְרָרִי וּשְׁנֵי חַיֵּי לֵוִי שֶׁבַע וּשְׁלֹשִׁים וּמְאַת שָׁנָה׃
בְּנֵי גֵרְשׁוֹן לִבְנִי וְשִׁמְעִי לְמִשְׁפְּחֹתָם׃
וּבְנֵי קְהָת עַמְרָם וְיִצְהָר וְחֶבְרוֹן וְעֻזִּיאֵל וּשְׁנֵי חַיֵּי קְהָת שָׁלֹשׁ וּשְׁלֹשִׁים וּמְאַת שָׁנָה׃
וּבְנֵי מְרָרִי מַחְלִי וּמוּשִׁי אֵלֶּה מִשְׁפְּחֹת הַלֵּוִי לְתֹלְדֹתָם׃
וַיִּקַּח עַמְרָם אֶת־יוֹכֶבֶד דֹּדָתוֹ לוֹ לְאִשָּׁה וַתֵּלֶד לוֹ אֶת־אַהֲרֹן וְאֶת־מֹשֶׁה וּשְׁנֵי חַיֵּי עַמְרָם שֶׁבַע וּשְׁלֹשִׁים וּמְאַת שָׁנָה׃
וּבְנֵי יִצְהָר קֹרַח וָנֶפֶג וְזִכְרִי׃
וּבְנֵי עֻזִּיאֵל מִישָׁאֵל וְאֶלְצָפָן וְסִתְרִי׃
וַיִּקַּח אַהֲרֹן אֶת־אֱלִישֶׁבַע בַּת־עַמִּינָדָב אֲחוֹת נַחְשׁוֹן לוֹ לְאִשָּׁה וַתֵּלֶד לוֹ אֶת־נָדָב וְאֶת־אֲבִיהוּא אֶת־אֶלְעָזָר וְאֶת־אִיתָמָר׃
וּבְנֵי קֹרַח אַסִּיר וְאֶלְקָנָה וַאֲבִיאָסָף אֵלֶּה מִשְׁפְּחֹת הַקָּרְחִי׃
וְאֶלְעָזָר בֶּן־אַהֲרֹן לָקַח־לוֹ מִבְּנוֹת פּוּטִיאֵל לוֹ לְאִשָּׁה וַתֵּלֶד לוֹ אֶת־פִּינְחָס אֵלֶּה רָאשֵׁי אֲבוֹת הַלְוִיִּם לְמִשְׁפְּחֹתָם׃
הוּא אַהֲרֹן וּמֹשֶׁה אֲשֶׁר אָמַר יְהוָה לָהֶם הוֹצִיאוּ אֶת־בְּנֵי יִשְׂרָאֵל מֵאֶרֶץ מִצְרַיִם עַל־צִבְאֹתָם׃
הֵם הַמְדַבְּרִים אֶל־פַּרְעֹה מֶלֶךְ־מִצְרַיִם לְהוֹצִיא אֶת־בְּנֵי־יִשְׂרָאֵל מִמִּצְרָיִם הוּא מֹשֶׁה וְאַהֲרֹן׃
וַיְהִי בְּיוֹם דִּבֶּר יְהוָה אֶל־מֹשֶׁה בְּאֶרֶץ מִצְרָיִם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר אֲנִי יְהוָה דַּבֵּר אֶל־פַּרְעֹה מֶלֶךְ מִצְרַיִם אֵת כָּל־אֲשֶׁר אֲנִי דֹּבֵר אֵלֶיךָ׃
וַיֹּאמֶר מֹשֶׁה לִפְנֵי יְהוָה הֵן אֲנִי עֲרַל שְׂפָתַיִם וְאֵיךְ יִשְׁמַע אֵלַי פַּרְעֹה׃

Chapter 7

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה רְאֵה נְתַתִּיךָ אֱלֹהִים לְפַרְעֹה וְאַהֲרֹן אָחִיךָ יִהְיֶה נְבִיאֶךָ׃
אַתָּה תְדַבֵּר אֵת כָּל־אֲשֶׁר אֲצַוֶּךָּ וְאַהֲרֹן אָחִיךָ יְדַבֵּר אֶל־פַּרְעֹה וְשִׁלַּח אֶת־בְּנֵי־יִשְׂרָאֵל מֵאַרְצוֹ׃
וַאֲנִי אַקְשֶׁה אֶת־לֵב פַּרְעֹה וְהִרְבֵּיתִי אֶת־אֹתֹתַי וְאֶת־מוֹפְתַי בְּאֶרֶץ מִצְרָיִם׃
וְלֹא־יִשְׁמַע אֲלֵכֶם פַּרְעֹה וְנָתַתִּי אֶת־יָדִי בְּמִצְרָיִם וְהוֹצֵאתִי אֶת־צִבְאֹתַי אֶת־עַמִּי בְנֵי־יִשְׂרָאֵל מֵאֶרֶץ מִצְרַיִם בִּשְׁפָטִים גְּדֹלִים׃
וְיָדְעוּ מִצְרַיִם כִּי־אֲנִי יְהוָה בִּנְטֹתִי אֶת־יָדִי עַל־מִצְרָיִם וְהוֹצֵאתִי אֶת־בְּנֵי־יִשְׂרָאֵל מִתּוֹכָם׃
וַיַּעַשׂ מֹשֶׁה וְאַהֲרֹן כַּאֲשֶׁר צִוָּה יְהוָה אֹתָם כֵּן עָשׂוּ׃
וּמֹשֶׁה בֶּן־שְׁמֹנִים שָׁנָה וְאַהֲרֹן בֶּן־שָׁלֹשׁ וּשְׁמֹנִים שָׁנָה בְּדַבְּרָם אֶל־פַּרְעֹה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
כִּי יְדַבֵּר אֲלֵכֶם פַּרְעֹה לֵאמֹר תְּנוּ לָכֶם מוֹפֵת וְאָמַרְתָּ אֶל־אַהֲרֹן קַח אֶת־מַטְּךָ וְהַשְׁלֵךְ לִפְנֵי־פַרְעֹה יְהִי לְתַנִּין׃
וַיָּבֹא מֹשֶׁה וְאַהֲרֹן אֶל־פַּרְעֹה וַיַּעַשׂוּ כֵן כַּאֲשֶׁר צִוָּה יְהוָה וַיַּשְׁלֵךְ אַהֲרֹן אֶת־מַטֵּהוּ לִפְנֵי פַרְעֹה וְלִפְנֵי עֲבָדָיו וַיְהִי לְתַנִּין׃
וַיִּקְרָא גַּם־פַּרְעֹה לַחֲכָמִים וְלַמְכַשְּׁפִים וַיַּעֲשׂוּ גַם־הֵם חַרְטֻמֵּי מִצְרַיִם בְּלַהֲטֵיהֶם כֵּן׃
וַיַּשְׁלִיכוּ אִישׁ מַטֵּהוּ וַיִּהְיוּ לְתַנִּינִם וַיִּבְלַע מַטֵּה־אַהֲרֹן אֶת־מַטֹּתָם׃
וַיֶּחֱזַק לֵב פַּרְעֹה וְלֹא שָׁמַע אֲלֵהֶם כַּאֲשֶׁר דִּבֶּר יְהוָה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה כָּבֵד לֵב פַּרְעֹה מֵאֵן לְשַׁלַּח הָעָם׃
לֵךְ אֶל־פַּרְעֹה בַּבֹּקֶר הִנֵּה יֹצֵא הַמַּיְמָה וְנִצַּבְתָּ לִקְרָאתוֹ עַל־שְׂפַת הַיְאֹר וְהַמַּטֶּה אֲשֶׁר־נֶהְפַּךְ לְנָחָשׁ תִּקַּח בְּיָדֶךָ׃
וְאָמַרְתָּ אֵלָיו יְהוָה אֱלֹהֵי הָעִבְרִים שְׁלָחַנִי אֵלֶיךָ לֵאמֹר שַׁלַּח אֶת־עַמִּי וְיַעַבְדֻנִי בַּמִּדְבָּר וְהִנֵּה לֹא־שָׁמַעְתָּ עַד־כֹּה׃
כֹּה אָמַר יְהוָה בְּזֹאת תֵּדַע כִּי אֲנִי יְהוָה הִנֵּה אָנֹכִי מַכֶּה בַּמַּטֶּה אֲשֶׁר־בְּיָדִי עַל־הַמַּיִם אֲשֶׁר בַּיְאֹר וְנֶהֶפְכוּ לְדָם׃
וְהַדָּגָה אֲשֶׁר־בַּיְאֹר תָּמוּת וּבָאַשׁ הַיְאֹר וְנִלְאוּ מִצְרַיִם לִשְׁתּוֹת מַיִם מִן־הַיְאֹר׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה אֱמֹר אֶל־אַהֲרֹן קַח מַטְּךָ וּנְטֵה־יָדְךָ עַל־מֵימֵי מִצְרַיִם עַל־נַהֲרֹתָם עַל־יְאֹרֵיהֶם וְעַל־אַגְמֵיהֶם וְעַל כָּל־מִקְוֵה מֵימֵיהֶם וְיִהְיוּ־דָם וְהָיָה דָם בְּכָל־אֶרֶץ מִצְרַיִם וּבָעֵצִים וּבָאֲבָנִים׃
וַיַּעֲשׂוּ־כֵן מֹשֶׁה וְאַהֲרֹן כַּאֲשֶׁר צִוָּה יְהוָה וַיָּרֶם בַּמַּטֶּה וַיַּךְ אֶת־הַמַּיִם אֲשֶׁר בַּיְאֹר לְעֵינֵי פַרְעֹה וּלְעֵינֵי עֲבָדָיו וַיֵּהָפְכוּ כָּל־הַמַּיִם אֲשֶׁר־בַּיְאֹר לְדָם׃
וְהַדָּגָה אֲשֶׁר־בַּיְאֹר מֵתָה וַיִּבְאַשׁ הַיְאֹר וְלֹא־יָכְלוּ מִצְרַיִם לִשְׁתּוֹת מַיִם מִן־הַיְאֹר וַיְהִי הַדָּם בְּכָל־אֶרֶץ מִצְרָיִם׃
וַיַּעֲשׂוּ־כֵן חַרְטֻמֵּי מִצְרַיִם בְּלָטֵיהֶם וַיֶּחֱזַק לֵב־פַּרְעֹה וְלֹא־שָׁמַע אֲלֵהֶם כַּאֲשֶׁר דִּבֶּר יְהוָה׃
וַיִּפֶן פַּרְעֹה וַיָּבֹא אֶל־בֵּיתוֹ וְלֹא־שָׁת לִבּוֹ גַּם־לָזֹאת׃
וַיַּחְפְּרוּ כָל־מִצְרַיִם סְבִיבֹת הַיְאֹר מַיִם לִשְׁתּוֹת כִּי לֹא יָכְלוּ לִשְׁתֹּת מִמֵּימֵי הַיְאֹר׃
וַיִּמָּלֵא שִׁבְעַת יָמִים אַחֲרֵי הַכּוֹת־יְהוָה אֶת־הַיְאֹר׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה בֹּא אֶל־פַּרְעֹה וְאָמַרְתָּ אֵלָיו כֹּה אָמַר יְהוָה שַׁלַּח אֶת־עַמִּי וְיַעַבְדֻנִי׃
וְאִם־מָאֵן אַתָּה לְשַׁלֵּחַ הִנֵּה אָנֹכִי נֹגֵף אֶת־כָּל־גְּבוּלְךָ בַּצְפַרְדְּעִים׃
וְשָׁרַץ הַיְאֹר צְפַרְדְּעִים וְעָלוּ וּבָאוּ בְּבֵיתֶךָ וּבַחֲדַר מִשְׁכָּבְךָ וְעַל־מִטָּתֶךָ וּבְבֵית עֲבָדֶיךָ וּבְעַמֶּךָ וּבְתַנּוּרֶיךָ וּבְמִשְׁאֲרוֹתֶיךָ׃
וּבְכָה וּבְעַמְּךָ וּבְכָל־עֲבָדֶיךָ יַעֲלוּ הַצְפַרְדְּעִים׃

Chapter 8

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה אֱמֹר אֶל־אַהֲרֹן נְטֵה אֶת־יָדְךָ בְּמַטֶּךָ עַל־הַנְּהָרֹת עַל־הַיְאֹרִים וְעַל־הָאֲגַמִּים וְהַעַל אֶת־הַצְפַרְדְּעִים עַל־אֶרֶץ מִצְרָיִם׃
וַיֵּט אַהֲרֹן אֶת־יָדוֹ עַל מֵימֵי מִצְרָיִם וַתַּעַל הַצְּפַרְדֵּעַ וַתְּכַס אֶת־אֶרֶץ מִצְרָיִם׃
וַיַּעֲשׂוּ־כֵן הַחֲרְטֻמִּים בְּלָטֵיהֶם וַיַּעֲלוּ אֶת־הַצְפַרְדְּעִים עַל־אֶרֶץ מִצְרָיִם׃
וַיִּקְרָא פַרְעֹה לְמֹשֶׁה וּלְאַהֲרֹן וַיֹּאמֶר הַעְתִּירוּ אֶל־יְהוָה וְיָסֵר הַצְפַרְדְּעִים מִמֶּנִּי וּמֵעַמִּי וַאֲשַׁלְּחָה אֶת־הָעָם וְיִזְבְּחוּ לַיהוָה׃
וַיֹּאמֶר מֹשֶׁה לְפַרְעֹה הִתְפָּאֵר עָלַי לְמָתַי אַעְתִּיר לְךָ וְלַעֲבָדֶיךָ וּלְעַמְּךָ לְהַכְרִית הַצֲפַרְדְּעִים מִמְּךָ וּמִבָּתֶּיךָ רַק בַּיְאֹר תִּשָּׁאַרְנָה׃
וַיֹּאמֶר לְמָחָר וַיֹּאמֶר כִּדְבָרְךָ לְמַעַן תֵּדַע כִּי־אֵין כַּיהוָה אֱלֹהֵינוּ׃
וְסָרוּ הַצְפַרְדְּעִים מִמְּךָ וּמִבָּתֶּיךָ וּמֵעֲבָדֶיךָ וּמֵעַמֶּךָ רַק בַּיְאֹר תִּשָּׁאַרְנָה׃
וַיֵּצֵא מֹשֶׁה וְאַהֲרֹן מֵעִם פַּרְעֹה וַיִּצְעַק מֹשֶׁה אֶל־יְהוָה עַל־דְּבַר הַצְפַרְדְּעִים אֲשֶׁר־שָׂם לְפַרְעֹה׃
וַיַּעַשׂ יְהוָה כִּדְבַר מֹשֶׁה וַיָּמֻתוּ הַצְפַרְדְּעִים מִן־הַבָּתִּים מִן־הַחֲצֵרֹת וּמִן־הַשָּׂדֹת׃
וַיִּצְבְּרוּ אֹתָם חֳמָרִם חֳמָרִם וַתִּבְאַשׁ הָאָרֶץ׃
וַיַּרְא פַּרְעֹה כִּי הָיְתָה הָרְוָחָה וְהַכְבֵּד אֶת־לִבּוֹ וְלֹא שָׁמַע אֲלֵהֶם כַּאֲשֶׁר דִּבֶּר יְהוָה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה אֱמֹר אֶל־אַהֲרֹן נְטֵה אֶת־מַטְּךָ וְהַךְ אֶת־עֲפַר הָאָרֶץ וְהָיָה לְכִנִּם בְּכָל־אֶרֶץ מִצְרָיִם׃
וַיַּעֲשׂוּ־כֵן וַיֵּט אַהֲרֹן אֶת־יָדוֹ בְמַטֵּהוּ וַיַּךְ אֶת־עֲפַר הָאָרֶץ וַתְּהִי הַכִּנָּם בָּאָדָם וּבַבְּהֵמָה כָּל־עֲפַר הָאָרֶץ הָיָה כִנִּים בְּכָל־אֶרֶץ מִצְרָיִם׃
וַיַּעֲשׂוּ־כֵן הַחַרְטֻמִּים בְּלָטֵיהֶם לְהוֹצִיא אֶת־הַכִּנִּים וְלֹא יָכֹלוּ וַתְּהִי הַכִּנָּם בָּאָדָם וּבַבְּהֵמָה׃
וַיֹּאמְרוּ הַחַרְטֻמִּים אֶל־פַּרְעֹה אֶצְבַּע אֱלֹהִים הִוא וַיֶּחֱזַק לֵב־פַּרְעֹה וְלֹא־שָׁמַע אֲלֵהֶם כַּאֲשֶׁר דִּבֶּר יְהוָה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה הַשְׁכֵּם בַּבֹּקֶר וְהִתְיַצֵּב לִפְנֵי פַרְעֹה הִנֵּה יוֹצֵא הַמָּיְמָה וְאָמַרְתָּ אֵלָיו כֹּה אָמַר יְהוָה שַׁלַּח עַמִּי וְיַעַבְדֻנִי׃
כִּי אִם־אֵינְךָ מְשַׁלֵּחַ אֶת־עַמִּי הִנְנִי מַשְׁלִיחַ בְּךָ וּבַעֲבָדֶיךָ וּבְעַמְּךָ וּבְבָתֶּיךָ אֶת־הֶעָרֹב וּמָלְאוּ בָּתֵּי מִצְרַיִם אֶת־הֶעָרֹב וְגַם הָאֲדָמָה אֲשֶׁר־הֵם עָלֶיהָ׃
וְהִפְלֵיתִי בַיּוֹם הַהוּא אֶת־אֶרֶץ גֹּשֶׁן אֲשֶׁר עַמִּי עֹמֵד עָלֶיהָ לְבִלְתִּי הֱיוֹת־שָׁם עָרֹב לְמַעַן תֵּדַע כִּי אֲנִי יְהוָה בְּקֶרֶב הָאָרֶץ׃
וְשַׂמְתִּי פְדֻת בֵּין עַמִּי וּבֵין עַמֶּךָ לְמָחָר יִהְיֶה הָאֹת הַזֶּה׃
וַיַּעַשׂ יְהוָה כֵּן וַיָּבֹא עָרֹב כָּבֵד בֵּיתָה פַרְעֹה וּבֵית עֲבָדָיו וּבְכָל־אֶרֶץ מִצְרַיִם תִּשָּׁחֵת הָאָרֶץ מִפְּנֵי הֶעָרֹב׃
וַיִּקְרָא פַרְעֹה אֶל־מֹשֶׁה וּלְאַהֲרֹן וַיֹּאמֶר לְכוּ זִבְחוּ לֵאלֹהֵיכֶם בָּאָרֶץ׃
וַיֹּאמֶר מֹשֶׁה לֹא נָכוֹן לַעֲשׂוֹת כֵּן כִּי תּוֹעֲבַת מִצְרַיִם נִזְבַּח לַיהוָה אֱלֹהֵינוּ הֵן נִזְבַּח אֶת־תּוֹעֲבַת מִצְרַיִם לְעֵינֵיהֶם וְלֹא יִסְקְלֻנוּ׃
דֶּרֶךְ שְׁלֹשֶׁת יָמִים נֵלֵךְ בַּמִּדְבָּר וְזָבַחְנוּ לַיהוָה אֱלֹהֵינוּ כַּאֲשֶׁר יֹאמַר אֵלֵינוּ׃
וַיֹּאמֶר פַּרְעֹה אָנֹכִי אֲשַׁלַּח אֶתְכֶם וּזְבַחְתֶּם לַיהוָה אֱלֹהֵיכֶם בַּמִּדְבָּר רַק הַרְחֵק לֹא־תַרְחִיקוּ לָלֶכֶת הַעְתִּירוּ בַּעֲדִי׃
וַיֹּאמֶר מֹשֶׁה הִנֵּה אָנֹכִי יוֹצֵא מֵעִמָּךְ וְהַעְתַּרְתִּי אֶל־יְהוָה וְסָר הֶעָרֹב מִפַּרְעֹה מֵעֲבָדָיו וּמֵעַמּוֹ מָחָר רַק אַל־יֹסֵף פַּרְעֹה הָתֵל לְבִלְתִּי שַׁלַּח אֶת־הָעָם לִזְבֹּחַ לַיהוָה׃
וַיֵּצֵא מֹשֶׁה מֵעִם פַּרְעֹה וַיֶּעְתַּר אֶל־יְהוָה׃
וַיַּעַשׂ יְהוָה כִּדְבַר מֹשֶׁה וַיָּסַר הֶעָרֹב מִפַּרְעֹה מֵעֲבָדָיו וּמֵעַמּוֹ לֹא נִשְׁאַר אֶחָד׃
וַיַּכְבֵּד פַּרְעֹה אֶת־לִבּוֹ גַּם בַּפַּעַם הַזֹּאת וְלֹא שִׁלַּח אֶת־הָעָם׃

Chapter 9

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה בֹּא אֶל־פַּרְעֹה וְדִבַּרְתָּ אֵלָיו כֹּה־אָמַר יְהוָה אֱלֹהֵי הָעִבְרִים שַׁלַּח אֶת־עַמִּי וְיַעַבְדֻנִי׃
כִּי אִם־מָאֵן אַתָּה לְשַׁלֵּחַ וְעוֹדְךָ מַחֲזִיק בָּם׃
הִנֵּה יַד־יְהוָה הוֹיָה בְּמִקְנְךָ אֲשֶׁר בַּשָּׂדֶה בַּסּוּסִים בַּחֲמֹרִים בַּגְּמַלִּים בַּבָּקָר וּבַצֹּאן דֶּבֶר כָּבֵד מְאֹד׃
וְהִפְלָה יְהוָה בֵּין מִקְנֵה יִשְׂרָאֵל וּבֵין מִקְנֵה מִצְרָיִם וְלֹא יָמוּת מִכָּל־לִבְנֵי יִשְׂרָאֵל דָּבָר׃
וַיָּשֶׂם יְהוָה מוֹעֵד לֵאמֹר מָחָר יַעֲשֶׂה יְהוָה הַדָּבָר הַזֶּה בָּאָרֶץ׃
וַיַּעַשׂ יְהוָה אֶת־הַדָּבָר הַזֶּה מִמָּחֳרָת וַיָּמָת כֹּל מִקְנֵה מִצְרָיִם וּמִמִּקְנֵה בְנֵי־יִשְׂרָאֵל לֹא־מֵת אֶחָד׃
וַיִּשְׁלַח פַּרְעֹה וְהִנֵּה לֹא־מֵת מִמִּקְנֵה יִשְׂרָאֵל עַד־אֶחָד וַיִּכְבַּד לֵב פַּרְעֹה וְלֹא שִׁלַּח אֶת־הָעָם׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן קְחוּ לָכֶם מְלֹא חָפְנֵיכֶם פִּיחַ כִּבְשָׁן וּזְרָקוֹ מֹשֶׁה הַשָּׁמַיְמָה לְעֵינֵי פַרְעֹה׃
וְהָיָה לְאָבָק עַל כָּל־אֶרֶץ מִצְרָיִם וְהָיָה עַל־הָאָדָם וְעַל־הַבְּהֵמָה לִשְׁחִין פֹּרֵחַ אֲבַעְבֻּעֹת בְּכָל־אֶרֶץ מִצְרָיִם׃
וַיִּקְחוּ אֶת־פִּיחַ הַכִּבְשָׁן וַיַּעַמְדוּ לִפְנֵי פַרְעֹה וַיִּזְרֹק אֹתוֹ מֹשֶׁה הַשָּׁמָיְמָה וַיְהִי שְׁחִין אֲבַעְבֻּעֹת פֹּרֵחַ בָּאָדָם וּבַבְּהֵמָה׃
וְלֹא־יָכְלוּ הַחַרְטֻמִּים לַעֲמֹד לִפְנֵי מֹשֶׁה מִפְּנֵי הַשְּׁחִין כִּי־הָיָה הַשְּׁחִין בַּחֲרְטֻמִּם וּבְכָל־מִצְרָיִם׃
וַיְחַזֵּק יְהוָה אֶת־לֵב פַּרְעֹה וְלֹא שָׁמַע אֲלֵהֶם כַּאֲשֶׁר דִּבֶּר יְהוָה אֶל־מֹשֶׁה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה הַשְׁכֵּם בַּבֹּקֶר וְהִתְיַצֵּב לִפְנֵי פַרְעֹה וְאָמַרְתָּ אֵלָיו כֹּה־אָמַר יְהוָה אֱלֹהֵי הָעִבְרִים שַׁלַּח אֶת־עַמִּי וְיַעַבְדֻנִי׃
כִּי בַּפַּעַם הַזֹּאת אֲנִי שֹׁלֵחַ אֶת־כָּל־מַגֵּפֹתַי אֶל־לִבְּךָ וּבַעֲבָדֶיךָ וּבְעַמֶּךָ בַּעֲבוּר תֵּדַע כִּי אֵין כָּמֹנִי בְּכָל־הָאָרֶץ׃
כִּי עַתָּה שָׁלַחְתִּי אֶת־יָדִי וָאַךְ אוֹתְךָ וְאֶת־עַמְּךָ בַּדָּבֶר וַתִּכָּחֵד מִן־הָאָרֶץ׃
וְאוּלָם בַּעֲבוּר זֹאת הֶעֱמַדְתִּיךָ בַּעֲבוּר הַרְאֹתְךָ אֶת־כֹּחִי וּלְמַעַן סַפֵּר שְׁמִי בְּכָל־הָאָרֶץ׃
עוֹדְךָ מִסְתּוֹלֵל בְּעַמִּי לְבִלְתִּי שַׁלְּחָם׃
הִנְנִי מַמְטִיר כָּעֵת מָחָר בָּרָד כָּבֵד מְאֹד אֲשֶׁר לֹא־הָיָה כָמֹהוּ בְּמִצְרַיִם לְמִן־הַיּוֹם הִוָּסְדָה וְעַד־עָתָּה׃
וְעַתָּה שְׁלַח הָעֵז אֶת־מִקְנְךָ וְאֵת כָּל־אֲשֶׁר לְךָ בַּשָּׂדֶה כָּל־הָאָדָם וְהַבְּהֵמָה אֲשֶׁר־יִמָּצֵא בַשָּׂדֶה וְלֹא יֵאָסֵף הַבַּיְתָה וְיָרַד עֲלֵהֶם הַבָּרָד וָמֵתוּ׃
הַיָּרֵא אֶת־דְּבַר יְהוָה מֵעַבְדֵי פַּרְעֹה הֵנִיס אֶת־עֲבָדָיו וְאֶת־מִקְנֵהוּ אֶל־הַבָּתִּים׃
וַאֲשֶׁר לֹא־שָׂם לִבּוֹ אֶל־דְּבַר יְהוָה וַיַּעֲזֹב אֶת־עֲבָדָיו וְאֶת־מִקְנֵהוּ בַּשָּׂדֶה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה נְטֵה אֶת־יָדְךָ עַל־הַשָּׁמַיִם וִיהִי בָרָד בְּכָל־אֶרֶץ מִצְרָיִם עַל־הָאָדָם וְעַל־הַבְּהֵמָה וְעַל כָּל־עֵשֶׂב הַשָּׂדֶה בְּאֶרֶץ מִצְרָיִם׃
וַיֵּט מֹשֶׁה אֶת־מַטֵּהוּ עַל־הַשָּׁמַיִם וַיהוָה נָתַן קֹלֹת וּבָרָד וַתִּהֲלַךְ אֵשׁ אָרְצָה וַיַּמְטֵר יְהוָה בָּרָד עַל־אֶרֶץ מִצְרָיִם׃
וַיְהִי בָרָד וְאֵשׁ מִתְלַקַּחַת בְּתוֹךְ הַבָּרָד כָּבֵד מְאֹד אֲשֶׁר לֹא־הָיָה כָמֹהוּ בְּכָל־אֶרֶץ מִצְרַיִם מֵאָז הָיְתָה לְגוֹי׃
וַיַּךְ הַבָּרָד בְּכָל־אֶרֶץ מִצְרַיִם אֵת כָּל־אֲשֶׁר בַּשָּׂדֶה מֵאָדָם וְעַד־בְּהֵמָה וְאֵת כָּל־עֵשֶׂב הַשָּׂדֶה הִכָּה הַבָּרָד וְאֶת־כָּל־עֵץ הַשָּׂדֶה שִׁבֵּר׃
רַק בְּאֶרֶץ גֹּשֶׁן אֲשֶׁר־שָׁם בְּנֵי יִשְׂרָאֵל לֹא הָיָה בָּרָד׃
וַיִּשְׁלַח פַּרְעֹה וַיִּקְרָא לְמֹשֶׁה וּלְאַהֲרֹן וַיֹּאמֶר אֲלֵהֶם חָטָאתִי הַפָּעַם יְהוָה הַצַּדִּיק וַאֲנִי וְעַמִּי הָרְשָׁעִים׃
הַעְתִּירוּ אֶל־יְהוָה וְרַב מִהְיֹת קֹלֹת אֱלֹהִים וּבָרָד וַאֲשַׁלְּחָה אֶתְכֶם וְלֹא תֹסִפוּן לַעֲמֹד׃
וַיֹּאמֶר אֵלָיו מֹשֶׁה כְּצֵאתִי אֶת־הָעִיר אֶפְרֹשׂ אֶת־כַּפַּי אֶל־יְהוָה הַקֹּלוֹת יֶחְדָּלוּן וְהַבָּרָד לֹא יִהְיֶה־עוֹד לְמַעַן תֵּדַע כִּי לַיהוָה הָאָרֶץ׃
וְאַתָּה וַעֲבָדֶיךָ יָדַעְתִּי כִּי טֶרֶם תִּירְאוּן מִפְּנֵי יְהוָה אֱלֹהִים׃
וְהַפִּשְׁתָּה וְהַשְּׂעֹרָה נֻכָּתָה כִּי הַשְּׂעֹרָה אָבִיב וְהַפִּשְׁתָּה גִּבְעֹל׃
וְהַחִטָּה וְהַכֻּסֶּמֶת לֹא נֻכּוּ כִּי אֲפִילֹת הֵנָּה׃
וַיֵּצֵא מֹשֶׁה מֵעִם פַּרְעֹה אֶת־הָעִיר וַיִּפְרֹשׂ כַּפָּיו אֶל־יְהוָה וַיַּחְדְּלוּ הַקֹּלוֹת וְהַבָּרָד וּמָטָר לֹא־נִתַּךְ אָרְצָה׃
וַיַּרְא פַּרְעֹה כִּי־חָדַל הַמָּטָר וְהַבָּרָד וְהַקֹּלֹת וַיֹּסֶף לַחֲטֹא וַיַּכְבֵּד לִבּוֹ הוּא וַעֲבָדָיו׃
וַיֶּחֱזַק לֵב פַּרְעֹה וְלֹא שִׁלַּח אֶת־בְּנֵי יִשְׂרָאֵל כַּאֲשֶׁר דִּבֶּר יְהוָה בְּיַד־מֹשֶׁה׃

Chapter 10

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה בֹּא אֶל־פַּרְעֹה כִּי־אֲנִי הִכְבַּדְתִּי אֶת־לִבּוֹ וְאֶת־לֵב עֲבָדָיו לְמַעַן שִׁתִי אֹתֹתַי אֵלֶּה בְּקִרְבּוֹ׃
וּלְמַעַן תְּסַפֵּר בְּאָזְנֵי בִנְךָ וּבֶן־בִּנְךָ אֵת אֲשֶׁר הִתְעַלַּלְתִּי בְּמִצְרַיִם וְאֶת־אֹתֹתַי אֲשֶׁר־שַׂמְתִּי בָם וִידַעְתֶּם כִּי־אֲנִי יְהוָה׃
וַיָּבֹא מֹשֶׁה וְאַהֲרֹן אֶל־פַּרְעֹה וַיֹּאמְרוּ אֵלָיו כֹּה־אָמַר יְהוָה אֱלֹהֵי הָעִבְרִים עַד־מָתַי מֵאַנְתָּ לֵעָנֹת מִפָּנָי שַׁלַּח עַמִּי וְיַעַבְדֻנִי׃
כִּי אִם־מָאֵן אַתָּה לְשַׁלֵּחַ אֶת־עַמִּי הִנְנִי מֵבִיא מָחָר אַרְבֶּה בִּגְבֻלֶךָ׃
וְכִסָּה אֶת־עֵין הָאָרֶץ וְלֹא יוּכַל לִרְאֹת אֶת־הָאָרֶץ וְאָכַל אֶת־יֶתֶר הַפְּלֵטָה הַנִּשְׁאֶרֶת לָכֶם מִן־הַבָּרָד וְאָכַל אֶת־כָּל־הָעֵץ הַצֹּמֵחַ לָכֶם מִן־הַשָּׂדֶה׃
וּמָלְאוּ בָתֶּיךָ וּבָתֵּי כָל־עֲבָדֶיךָ וּבָתֵּי כָל־מִצְרַיִם אֲשֶׁר לֹא־רָאוּ אֲבֹתֶיךָ וַאֲבוֹת אֲבֹתֶיךָ מִיּוֹם הֱיוֹתָם עַל־הָאֲדָמָה עַד הַיּוֹם הַזֶּה וַיִּפֶן וַיֵּצֵא מֵעִם פַּרְעֹה׃
וַיֹּאמְרוּ עַבְדֵי פַרְעֹה אֵלָיו עַד־מָתַי יִהְיֶה זֶה לָנוּ לְמוֹקֵשׁ שַׁלַּח אֶת־הָאֲנָשִׁים וְיַעַבְדוּ אֶת־יְהוָה אֱלֹהֵיהֶם הֲטֶרֶם תֵּדַע כִּי אָבְדָה מִצְרָיִם׃
וַיּוּשַׁב אֶת־מֹשֶׁה וְאֶת־אַהֲרֹן אֶל־פַּרְעֹה וַיֹּאמֶר אֲלֵהֶם לְכוּ עִבְדוּ אֶת־יְהוָה אֱלֹהֵיכֶם מִי וָמִי הַהֹלְכִים׃
וַיֹּאמֶר מֹשֶׁה בִּנְעָרֵינוּ וּבִזְקֵנֵינוּ נֵלֵךְ בְּבָנֵינוּ וּבִבְנוֹתֵנוּ בְּצֹאנֵנוּ וּבִבְקָרֵנוּ נֵלֵךְ כִּי חַג־יְהוָה לָנוּ׃
וַיֹּאמֶר אֲלֵהֶם יְהִי כֵן יְהוָה עִמָּכֶם כַּאֲשֶׁר אֲשַׁלַּח אֶתְכֶם וְאֶת־טַפְּכֶם רְאוּ כִּי רָעָה נֶגֶד פְּנֵיכֶם׃
לֹא כֵן לְכוּ־נָא הַגְּבָרִים וְעִבְדוּ אֶת־יְהוָה כִּי אֹתָהּ אַתֶּם מְבַקְשִׁים וַיְגָרֶשׁ אֹתָם מֵאֵת פְּנֵי פַרְעֹה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה נְטֵה יָדְךָ עַל־אֶרֶץ מִצְרַיִם בָּאַרְבֶּה וְיַעַל עַל־אֶרֶץ מִצְרָיִם וְיֹאכַל אֶת־כָּל־עֵשֶׂב הָאָרֶץ אֵת כָּל־אֲשֶׁר הִשְׁאִיר הַבָּרָד׃
וַיֵּט מֹשֶׁה אֶת־מַטֵּהוּ עַל־אֶרֶץ מִצְרַיִם וַיהוָה נִהַג רוּחַ קָדִים בָּאָרֶץ כָּל־הַיּוֹם הַהוּא וְכָל־הַלָּיְלָה הַבֹּקֶר הָיָה וְרוּחַ הַקָּדִים נָשָׂא אֶת־הָאַרְבֶּה׃
וַיַּעַל הָאַרְבֶּה עַל כָּל־אֶרֶץ מִצְרַיִם וַיָּנַח בְּכֹל גְּבוּל מִצְרָיִם כָּבֵד מְאֹד לְפָנָיו לֹא־הָיָה כֵן אַרְבֶּה כָּמֹהוּ וְאַחֲרָיו לֹא יִהְיֶה־כֵּן׃
וַיְכַס אֶת־עֵין כָּל־הָאָרֶץ וַתֶּחְשַׁךְ הָאָרֶץ וַיֹּאכַל אֶת־כָּל־עֵשֶׂב הָאָרֶץ וְאֵת כָּל־פְּרִי הָעֵץ אֲשֶׁר הוֹתִיר הַבָּרָד וְלֹא־נוֹתַר כָּל־יֶרֶק בָּעֵץ וּבְעֵשֶׂב הַשָּׂדֶה בְּכָל־אֶרֶץ מִצְרָיִם׃
וַיְמַהֵר פַּרְעֹה לִקְרֹא לְמֹשֶׁה וּלְאַהֲרֹן וַיֹּאמֶר חָטָאתִי לַיהוָה אֱלֹהֵיכֶם וְלָכֶם׃
וְעַתָּה שָׂא נָא חַטָּאתִי אַךְ הַפַּעַם וְהַעְתִּירוּ לַיהוָה אֱלֹהֵיכֶם וְיָסֵר מֵעָלַי רַק אֶת־הַמָּוֶת הַזֶּה׃
וַיֵּצֵא מֵעִם פַּרְעֹה וַיֶּעְתַּר אֶל־יְהוָה׃
וַיַּהֲפֹךְ יְהוָה רוּחַ־יָם חָזָק מְאֹד וַיִּשָּׂא אֶת־הָאַרְבֶּה וַיִּתְקָעֵהוּ יָמָּה סּוּף לֹא נִשְׁאַר אַרְבֶּה אֶחָד בְּכֹל גְּבוּל מִצְרָיִם׃
וַיְחַזֵּק יְהוָה אֶת־לֵב פַּרְעֹה וְלֹא שִׁלַּח אֶת־בְּנֵי יִשְׂרָאֵל׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה נְטֵה יָדְךָ עַל־הַשָּׁמַיִם וִיהִי חֹשֶׁךְ עַל־אֶרֶץ מִצְרָיִם וְיָמֵשׁ חֹשֶׁךְ׃
וַיֵּט מֹשֶׁה אֶת־יָדוֹ עַל־הַשָּׁמָיִם וַיְהִי חֹשֶׁךְ־אֲפֵלָה בְּכָל־אֶרֶץ מִצְרַיִם שְׁלֹשֶׁת יָמִים׃
לֹא־רָאוּ אִישׁ אֶת־אָחִיו וְלֹא־קָמוּ אִישׁ מִתַּחְתָּיו שְׁלֹשֶׁת יָמִים וּלְכָל־בְּנֵי יִשְׂרָאֵל הָיָה אוֹר בְּמוֹשְׁבֹתָם׃
וַיִּקְרָא פַרְעֹה אֶל־מֹשֶׁה וַיֹּאמֶר לְכוּ עִבְדוּ אֶת־יְהוָה רַק צֹאנְכֶם וּבְקַרְכֶם יֻצָּג גַּם־טַפְּכֶם יֵלֵךְ עִמָּכֶם׃
וַיֹּאמֶר מֹשֶׁה גַּם־אַתָּה תִּתֵּן בְּיָדֵנוּ זְבָחִים וְעֹלוֹת וְעָשִׂינוּ לַיהוָה אֱלֹהֵינוּ׃
וְגַם־מִקְנֵנוּ יֵלֵךְ עִמָּנוּ לֹא תִשָּׁאֵר פַּרְסָה כִּי מִמֶּנּוּ נִקַּח לַעֲבֹד אֶת־יְהוָה אֱלֹהֵינוּ וַאֲנַחְנוּ לֹא־נֵדַע מַה־נַּעֲבֹד אֶת־יְהוָה עַד־בֹּאֵנוּ שָׁמָּה׃
וַיְחַזֵּק יְהוָה אֶת־לֵב פַּרְעֹה וְלֹא אָבָה לְשַׁלְּחָם׃
וַיֹּאמֶר־לוֹ פַרְעֹה לֵךְ מֵעָלָי הִשָּׁמֶר לְךָ אֶל־תֹּסֶף רְאוֹת פָּנַי כִּי בְּיוֹם רְאֹתְךָ פָנַי תָּמוּת׃
וַיֹּאמֶר מֹשֶׁה כֵּן דִּבַּרְתָּ לֹא־אֹסִף עוֹד רְאוֹת פָּנֶיךָ׃

Chapter 11

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עוֹד נֶגַע אֶחָד אָבִיא עַל־פַּרְעֹה וְעַל־מִצְרַיִם אַחֲרֵי־כֵן יְשַׁלַּח אֶתְכֶם מִזֶּה כְּשַׁלְּחוֹ כָּלָה גָּרֵשׁ יְגָרֵשׁ אֶתְכֶם מִזֶּה׃
דַּבֶּר־נָא בְּאָזְנֵי הָעָם וְיִשְׁאֲלוּ אִישׁ מֵאֵת רֵעֵהוּ וְאִשָּׁה מֵאֵת רְעוּתָהּ כְּלֵי־כֶסֶף וּכְלֵי זָהָב׃
וַיִּתֵּן יְהוָה אֶת־חֵן הָעָם בְּעֵינֵי מִצְרָיִם גַּם הָאִישׁ מֹשֶׁה גָּדוֹל מְאֹד בְּאֶרֶץ מִצְרַיִם בְּעֵינֵי עַבְדֵי־פַרְעֹה וּבְעֵינֵי הָעָם׃
וַיֹּאמֶר מֹשֶׁה כֹּה אָמַר יְהוָה כַּחֲצֹת הַלַּיְלָה אֲנִי יוֹצֵא בְּתוֹךְ מִצְרָיִם׃
וּמֵת כָּל־בְּכוֹר בְּאֶרֶץ מִצְרַיִם מִבְּכוֹר פַּרְעֹה הַיֹּשֵׁב עַל־כִּסְאוֹ עַד בְּכוֹר הַשִּׁפְחָה אֲשֶׁר אַחַר הָרֵחָיִם וְכֹל בְּכוֹר בְּהֵמָה׃
וְהָיְתָה צְעָקָה גְדֹלָה בְּכָל־אֶרֶץ מִצְרָיִם אֲשֶׁר כָּמֹהוּ לֹא נִהְיָתָה וְכָמֹהוּ לֹא תֹסִף׃
וּלְכֹל בְּנֵי יִשְׂרָאֵל לֹא יֶחֱרַץ־כֶּלֶב לְשֹׁנוֹ לְמֵאִישׁ וְעַד־בְּהֵמָה לְמַעַן תֵּדְעוּן אֲשֶׁר יַפְלֶה יְהוָה בֵּין מִצְרַיִם וּבֵין יִשְׂרָאֵל׃
וְיָרְדוּ כָל־עֲבָדֶיךָ אֵלֶּה אֵלַי וְהִשְׁתַּחֲוּוּ־לִי לֵאמֹר צֵא אַתָּה וְכָל־הָעָם אֲשֶׁר־בְּרַגְלֶיךָ וְאַחֲרֵי־כֵן אֵצֵא וַיֵּצֵא מֵעִם־פַּרְעֹה בָּחֳרִי־אָף׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה לֹא־יִשְׁמַע אֲלֵיכֶם פַּרְעֹה לְמַעַן רְבוֹת מוֹפְתַי בְּאֶרֶץ מִצְרָיִם׃
וּמֹשֶׁה וְאַהֲרֹן עָשׂוּ אֶת־כָּל־הַמֹּפְתִים הָאֵלֶּה לִפְנֵי פַרְעֹה וַיְחַזֵּק יְהוָה אֶת־לֵב פַּרְעֹה וְלֹא־שִׁלַּח אֶת־בְּנֵי־יִשְׂרָאֵל מֵאַרְצוֹ׃

Chapter 12

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן בְּאֶרֶץ מִצְרַיִם לֵאמֹר׃
הַחֹדֶשׁ הַזֶּה לָכֶם רֹאשׁ חֳדָשִׁים רִאשׁוֹן הוּא לָכֶם לְחָדְשֵׁי הַשָּׁנָה׃
דַּבְּרוּ אֶל־כָּל־עֲדַת יִשְׂרָאֵל לֵאמֹר בֶּעָשֹׂר לַחֹדֶשׁ הַזֶּה וְיִקְחוּ לָהֶם אִישׁ שֶׂה לְבֵית־אָבֹת שֶׂה לַבָּיִת׃
וְאִם־יִמְעַט הַבַּיִת מִהְיֹת מִשֶּׂה וְלָקַח הוּא וּשְׁכֵנוֹ הַקָּרֹב אֶל־בֵּיתוֹ בְּמִכְסַת נְפָשֹׁת אִישׁ לְפִי אָכְלוֹ תָּכֹסּוּ עַל־הַשֶּׂה׃
שֶׂה תָמִים זָכָר בֶּן־שָׁנָה יִהְיֶה לָכֶם מִן־הַכְּבָשִׂים וּמִן־הָעִזִּים תִּקָּחוּ׃
וְהָיָה לָכֶם לְמִשְׁמֶרֶת עַד אַרְבָּעָה עָשָׂר יוֹם לַחֹדֶשׁ הַזֶּה וְשָׁחֲטוּ אֹתוֹ כֹּל קְהַל עֲדַת־יִשְׂרָאֵל בֵּין הָעַרְבָּיִם׃
וְלָקְחוּ מִן־הַדָּם וְנָתְנוּ עַל־שְׁתֵּי הַמְּזוּזֹת וְעַל־הַמַּשְׁקוֹף עַל הַבָּתִּים אֲשֶׁר־יֹאכְלוּ אֹתוֹ בָּהֶם׃
וְאָכְלוּ אֶת־הַבָּשָׂר בַּלַּיְלָה הַזֶּה צְלִי־אֵשׁ וּמַצּוֹת עַל־מְרֹרִים יֹאכְלֻהוּ׃
אַל־תֹּאכְלוּ מִמֶּנּוּ נָא וּבָשֵׁל מְבֻשָּׁל בַּמָּיִם כִּי אִם־צְלִי־אֵשׁ רֹאשׁוֹ עַל־כְּרָעָיו וְעַל־קִרְבּוֹ׃
וְלֹא־תוֹתִירוּ מִמֶּנּוּ עַד־בֹּקֶר וְהַנֹּתָר מִמֶּנּוּ עַד־בֹּקֶר בָּאֵשׁ תִּשְׂרֹפוּ׃
וְכָכָה תֹּאכְלוּ אֹתוֹ מָתְנֵיכֶם חֲגֻרִים נַעֲלֵיכֶם בְּרַגְלֵיכֶם וּמַקֶּלְכֶם בְּיֶדְכֶם וַאֲכַלְתֶּם אֹתוֹ בְּחִפָּזוֹן פֶּסַח הוּא לַיהוָה׃
וְעָבַרְתִּי בְאֶרֶץ־מִצְרַיִם בַּלַּיְלָה הַזֶּה וְהִכֵּיתִי כָל־בְּכוֹר בְּאֶרֶץ מִצְרַיִם מֵאָדָם וְעַד־בְּהֵמָה וּבְכָל־אֱלֹהֵי מִצְרַיִם אֶעֱשֶׂה שְׁפָטִים אֲנִי יְהוָה׃
וְהָיָה הַדָּם לָכֶם לְאֹת עַל הַבָּתִּים אֲשֶׁר אַתֶּם שָׁם וְרָאִיתִי אֶת־הַדָּם וּפָסַחְתִּי עֲלֵכֶם וְלֹא־יִהְיֶה בָכֶם נֶגֶף לְמַשְׁחִית בְּהַכֹּתִי בְּאֶרֶץ מִצְרָיִם׃
וְהָיָה הַיּוֹם הַזֶּה לָכֶם לְזִכָּרוֹן וְחַגֹּתֶם אֹתוֹ חַג לַיהוָה לְדֹרֹתֵיכֶם חֻקַּת עוֹלָם תְּחָגֻּהוּ׃
שִׁבְעַת יָמִים מַצּוֹת תֹּאכֵלוּ אַךְ בַּיּוֹם הָרִאשׁוֹן תַּשְׁבִּיתוּ שְּׂאֹר מִבָּתֵּיכֶם כִּי כָּל־אֹכֵל חָמֵץ וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מִיִּשְׂרָאֵל מִיּוֹם הָרִאשֹׁן עַד־יוֹם הַשְּׁבִעִי׃
וּבַיּוֹם הָרִאשׁוֹן מִקְרָא־קֹדֶשׁ וּבַיּוֹם הַשְּׁבִיעִי מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם כָּל־מְלָאכָה לֹא־יֵעָשֶׂה בָהֶם אַךְ אֲשֶׁר יֵאָכֵל לְכָל־נֶפֶשׁ הוּא לְבַדּוֹ יֵעָשֶׂה לָכֶם׃
וּשְׁמַרְתֶּם אֶת־הַמַּצּוֹת כִּי בְּעֶצֶם הַיּוֹם הַזֶּה הוֹצֵאתִי אֶת־צִבְאוֹתֵיכֶם מֵאֶרֶץ מִצְרָיִם וּשְׁמַרְתֶּם אֶת־הַיּוֹם הַזֶּה לְדֹרֹתֵיכֶם חֻקַּת עוֹלָם׃
בָּרִאשֹׁן בְּאַרְבָּעָה עָשָׂר יוֹם לַחֹדֶשׁ בָּעֶרֶב תֹּאכְלוּ מַצֹּת עַד יוֹם הָאֶחָד וְעֶשְׂרִים לַחֹדֶשׁ בָּעָרֶב׃
שִׁבְעַת יָמִים שְׂאֹר לֹא יִמָּצֵא בְּבָתֵּיכֶם כִּי כָּל־אֹכֵל מַחְמֶצֶת וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מֵעֲדַת יִשְׂרָאֵל בַּגֵּר וּבְאֶזְרַח הָאָרֶץ׃
כָּל־מַחְמֶצֶת לֹא תֹאכֵלוּ בְּכֹל מוֹשְׁבֹתֵיכֶם תֹּאכְלוּ מַצּוֹת׃
וַיִּקְרָא מֹשֶׁה לְכָל־זִקְנֵי יִשְׂרָאֵל וַיֹּאמֶר אֲלֵהֶם מִשְׁכוּ וּקְחוּ לָכֶם צֹאן לְמִשְׁפְּחֹתֵיכֶם וְשַׁחֲטוּ הַפָּסַח׃
וּלְקַחְתֶּם אֲגֻדַּת אֵזוֹב וּטְבַלְתֶּם בַּדָּם אֲשֶׁר־בַּסַּף וְהִגַּעְתֶּם אֶל־הַמַּשְׁקוֹף וְאֶל־שְׁתֵּי הַמְּזוּזֹת מִן־הַדָּם אֲשֶׁר בַּסָּף וְאַתֶּם לֹא תֵצְאוּ אִישׁ מִפֶּתַח־בֵּיתוֹ עַד־בֹּקֶר׃
וְעָבַר יְהוָה לִנְגֹּף אֶת־מִצְרַיִם וְרָאָה אֶת־הַדָּם עַל־הַמַּשְׁקוֹף וְעַל שְׁתֵּי הַמְּזוּזֹת וּפָסַח יְהוָה עַל־הַפֶּתַח וְלֹא יִתֵּן הַמַּשְׁחִית לָבֹא אֶל־בָּתֵּיכֶם לִנְגֹּף׃
וּשְׁמַרְתֶּם אֶת־הַדָּבָר הַזֶּה לְחָק־לְךָ וּלְבָנֶיךָ עַד־עוֹלָם׃
וְהָיָה כִּי־תָבֹאוּ אֶל־הָאָרֶץ אֲשֶׁר יִתֵּן יְהוָה לָכֶם כַּאֲשֶׁר דִּבֵּר וּשְׁמַרְתֶּם אֶת־הָעֲבֹדָה הַזֹּאת׃
וְהָיָה כִּי־יֹאמְרוּ אֲלֵיכֶם בְּנֵיכֶם מָה הָעֲבֹדָה הַזֹּאת לָכֶם׃
וַאֲמַרְתֶּם זֶבַח־פֶּסַח הוּא לַיהוָה אֲשֶׁר פָּסַח עַל־בָּתֵּי בְנֵי־יִשְׂרָאֵל בְּמִצְרַיִם בְּנָגְפּוֹ אֶת־מִצְרַיִם וְאֶת־בָּתֵּינוּ הִצִּיל וַיִּקֹּד הָעָם וַיִּשְׁתַּחֲוּוּ׃
וַיֵּלְכוּ וַיַּעֲשׂוּ בְּנֵי יִשְׂרָאֵל כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה וְאַהֲרֹן כֵּן עָשׂוּ׃
וַיְהִי בַּחֲצִי הַלַּיְלָה וַיהוָה הִכָּה כָל־בְּכוֹר בְּאֶרֶץ מִצְרַיִם מִבְּכֹר פַּרְעֹה הַיֹּשֵׁב עַל־כִּסְאוֹ עַד בְּכוֹר הַשְּׁבִי אֲשֶׁר בְּבֵית הַבּוֹר וְכֹל בְּכוֹר בְּהֵמָה׃
וַיָּקָם פַּרְעֹה לַיְלָה הוּא וְכָל־עֲבָדָיו וְכָל־מִצְרַיִם וַתְּהִי צְעָקָה גְדֹלָה בְּמִצְרָיִם כִּי־אֵין בַּיִת אֲשֶׁר אֵין־שָׁם מֵת׃
וַיִּקְרָא לְמֹשֶׁה וּלְאַהֲרֹן לַיְלָה וַיֹּאמֶר קוּמוּ צְּאוּ מִתּוֹךְ עַמִּי גַּם־אַתֶּם גַּם־בְּנֵי יִשְׂרָאֵל וּלְכוּ עִבְדוּ אֶת־יְהוָה כְּדַבֶּרְכֶם׃
גַּם־צֹאנְכֶם גַּם־בְּקַרְכֶם קְחוּ כַּאֲשֶׁר דִּבַּרְתֶּם וָלֵכוּ וּבֵרַכְתֶּם גַּם־אֹתִי׃
וַתֶּחֱזַק מִצְרַיִם עַל־הָעָם לְמַהֵר לְשַׁלְּחָם מִן־הָאָרֶץ כִּי אָמְרוּ כֻּלָּנוּ מֵתִים׃
וַיִּשָּׂא הָעָם אֶת־בְּצֵקוֹ טֶרֶם יֶחְמָץ מִשְׁאֲרֹתָם צְרֻרֹת בְּשִׂמְלֹתָם עַל־שִׁכְמָם׃
וּבְנֵי־יִשְׂרָאֵל עָשׂוּ כִּדְבַר מֹשֶׁה וַיִּשְׁאֲלוּ מִמִּצְרַיִם כְּלֵי־כֶסֶף וּכְלֵי זָהָב וּשְׂמָלֹת׃
וַיהוָה נָתַן אֶת־חֵן הָעָם בְּעֵינֵי מִצְרַיִם וַיַּשְׁאִלוּם וַיְנַצְּלוּ אֶת־מִצְרָיִם׃
וַיִּסְעוּ בְנֵי־יִשְׂרָאֵל מֵרַעְמְסֵס סֻכֹּתָה כְּשֵׁשׁ־מֵאוֹת אֶלֶף רַגְלִי הַגְּבָרִים לְבַד מִטָּף׃
וְגַם־עֵרֶב רַב עָלָה אִתָּם וְצֹאן וּבָקָר מִקְנֶה כָּבֵד מְאֹד׃
וַיֹּאפוּ אֶת־הַבָּצֵק אֲשֶׁר הוֹצִיאוּ מִמִּצְרַיִם עֻגֹת מַצּוֹת כִּי לֹא חָמֵץ כִּי־גֹרְשׁוּ מִמִּצְרַיִם וְלֹא יָכְלוּ לְהִתְמַהְמֵהַּ וְגַם־צֵדָה לֹא־עָשׂוּ לָהֶם׃
וּמוֹשַׁב בְּנֵי יִשְׂרָאֵל אֲשֶׁר יָשְׁבוּ בְּמִצְרָיִם שְׁלֹשִׁים שָׁנָה וְאַרְבַּע מֵאוֹת שָׁנָה׃
וַיְהִי מִקֵּץ שְׁלֹשִׁים שָׁנָה וְאַרְבַּע מֵאוֹת שָׁנָה וַיְהִי בְּעֶצֶם הַיּוֹם הַזֶּה יָצְאוּ כָּל־צִבְאוֹת יְהוָה מֵאֶרֶץ מִצְרָיִם׃
לֵיל שִׁמֻּרִים הוּא לַיהוָה לְהוֹצִיאָם מֵאֶרֶץ מִצְרָיִם הוּא־הַלַּיְלָה הַזֶּה לַיהוָה שִׁמֻּרִים לְכָל־בְּנֵי יִשְׂרָאֵל לְדֹרֹתָם׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאַהֲרֹן זֹאת חֻקַּת הַפָּסַח כָּל־בֶּן־נֵכָר לֹא־יֹאכַל בּוֹ׃
וְכָל־עֶבֶד אִישׁ מִקְנַת־כָּסֶף וּמַלְתָּה אֹתוֹ אָז יֹאכַל בּוֹ׃
תּוֹשָׁב וְשָׂכִיר לֹא־יֹאכַל־בּוֹ׃
בְּבַיִת אֶחָד יֵאָכֵל לֹא־תוֹצִיא מִן־הַבַּיִת מִן־הַבָּשָׂר חוּצָה וְעֶצֶם לֹא תִשְׁבְּרוּ־בוֹ׃
כָּל־עֲדַת יִשְׂרָאֵל יַעֲשׂוּ אֹתוֹ׃
וְכִי־יָגוּר אִתְּךָ גֵּר וְעָשָׂה פֶסַח לַיהוָה הִמּוֹל לוֹ כָל־זָכָר וְאָז יִקְרַב לַעֲשֹׂתוֹ וְהָיָה כְּאֶזְרַח הָאָרֶץ וְכָל־עָרֵל לֹא־יֹאכַל בּוֹ׃
תּוֹרָה אַחַת יִהְיֶה לָאֶזְרָח וְלַגֵּר הַגָּר בְּתוֹכְכֶם׃
וַיַּעֲשׂוּ כָּל־בְּנֵי יִשְׂרָאֵל כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה וְאֶת־אַהֲרֹן כֵּן עָשׂוּ׃
וַיְהִי בְּעֶצֶם הַיּוֹם הַזֶּה הוֹצִיא יְהוָה אֶת־בְּנֵי יִשְׂרָאֵל מֵאֶרֶץ מִצְרַיִם עַל־צִבְאֹתָם׃

Chapter 13

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
קַדֶּשׁ־לִי כָל־בְּכוֹר פֶּטֶר כָּל־רֶחֶם בִּבְנֵי יִשְׂרָאֵל בָּאָדָם וּבַבְּהֵמָה לִי הוּא׃
וַיֹּאמֶר מֹשֶׁה אֶל־הָעָם זָכוֹר אֶת־הַיּוֹם הַזֶּה אֲשֶׁר יְצָאתֶם מִמִּצְרַיִם מִבֵּית עֲבָדִים כִּי בְּחֹזֶק יָד הוֹצִיא יְהֹוָה אֶתְכֶם מִזֶּה וְלֹא יֵאָכֵל חָמֵץ׃
הַיּוֹם אַתֶּם יֹצְאִים בְּחֹדֶשׁ הָאָבִיב׃
וְהָיָה כִי־יְבִיאֲךָ יְהוָה אֶל־אֶרֶץ הַכְּנַעֲנִי וְהַחִתִּי וְהָאֱמֹרִי וְהַחִוִּי וְהַיְבוּסִי אֲשֶׁר נִשְׁבַּע לַאֲבֹתֶיךָ לָתֶת לָךְ אֶרֶץ זָבַת חָלָב וּדְבָשׁ וְעָבַדְתָּ אֶת־הָעֲבֹדָה הַזֹּאת בַּחֹדֶשׁ הַזֶּה׃
שִׁבְעַת יָמִים תֹּאכַל מַצֹּת וּבַיּוֹם הַשְּׁבִיעִי חַג לַיהוָה׃
מַצּוֹת יֵאָכֵל אֵת שִׁבְעַת הַיָּמִים וְלֹא־יֵרָאֶה לְךָ חָמֵץ וְלֹא־יֵרָאֶה לְךָ שְׂאֹר בְּכָל־גְּבֻלֶךָ׃
וְהִגַּדְתָּ לְבִנְךָ בַּיּוֹם הַהוּא לֵאמֹר בַּעֲבוּר זֶה עָשָׂה יְהוָה לִי בְּצֵאתִי מִמִּצְרָיִם׃
וְהָיָה לְךָ לְאוֹת עַל־יָדְךָ וּלְזִכָּרוֹן בֵּין עֵינֶיךָ לְמַעַן תִּהְיֶה תּוֹרַת יְהוָה בְּפִיךָ כִּי בְּיָד חֲזָקָה הוֹצִאֲךָ יְהֹוָה מִמִּצְרָיִם׃
וְשָׁמַרְתָּ אֶת־הַחֻקָּה הַזֹּאת לְמוֹעֲדָהּ מִיָּמִים יָמִימָה׃
וְהָיָה כִּי־יְבִאֲךָ יְהוָה אֶל־אֶרֶץ הַכְּנַעֲנִי כַּאֲשֶׁר נִשְׁבַּע לְךָ וְלַאֲבֹתֶיךָ וּנְתָנָהּ לָךְ׃
וְהַעֲבַרְתָּ כָל־פֶּטֶר־רֶחֶם לַיהֹוָה וְכָל־פֶּטֶר שֶׁגֶר בְּהֵמָה אֲשֶׁר יִהְיֶה לְךָ הַזְּכָרִים לַיהוָה׃
וְכָל־פֶּטֶר חֲמֹר תִּפְדֶּה בְשֶׂה וְאִם־לֹא תִפְדֶּה וַעֲרַפְתּוֹ וְכֹל בְּכוֹר אָדָם בְּבָנֶיךָ תִּפְדֶּה׃
וְהָיָה כִּי־יִשְׁאָלְךָ בִנְךָ מָחָר לֵאמֹר מַה־זֹּאת וְאָמַרְתָּ אֵלָיו בְּחֹזֶק יָד הוֹצִיאָנוּ יְהוָה מִמִּצְרַיִם מִבֵּית עֲבָדִים׃
וַיְהִי כִּי־הִקְשָׁה פַרְעֹה לְשַׁלְּחֵנוּ וַיַּהֲרֹג יְהֹוָה כָּל־בְּכוֹר בְּאֶרֶץ מִצְרַיִם מִבְּכֹר אָדָם וְעַד־בְּכוֹר בְּהֵמָה עַל־כֵּן אֲנִי זֹבֵחַ לַיהוָה כָּל־פֶּטֶר רֶחֶם הַזְּכָרִים וְכָל־בְּכוֹר בָּנַי אֶפְדֶּה׃
וְהָיָה לְאוֹת עַל־יָדְכָה וּלְטוֹטָפֹת בֵּין עֵינֶיךָ כִּי בְּחֹזֶק יָד הוֹצִיאָנוּ יְהוָה מִמִּצְרָיִם׃
וַיְהִי בְּשַׁלַּח פַּרְעֹה אֶת־הָעָם וְלֹא־נָחָם אֱלֹהִים דֶּרֶךְ אֶרֶץ פְּלִשְׁתִּים כִּי קָרוֹב הוּא כִּי אָמַר אֱלֹהִים פֶּן־יִנָּחֵם הָעָם בִּרְאֹתָם מִלְחָמָה וְשָׁבוּ מִצְרָיְמָה׃
וַיַּסֵּב אֱלֹהִים אֶת־הָעָם דֶּרֶךְ הַמִּדְבָּר יַם־סוּף וַחֲמֻשִׁים עָלוּ בְנֵי־יִשְׂרָאֵל מֵאֶרֶץ מִצְרָיִם׃
וַיִּקַּח מֹשֶׁה אֶת־עַצְמוֹת יוֹסֵף עִמּוֹ כִּי הַשְׁבֵּעַ הִשְׁבִּיעַ אֶת־בְּנֵי יִשְׂרָאֵל לֵאמֹר פָּקֹד יִפְקֹד אֱלֹהִים אֶתְכֶם וְהַעֲלִיתֶם אֶת־עַצְמֹתַי מִזֶּה אִתְּכֶם׃
וַיִּסְעוּ מִסֻּכֹּת וַיַּחֲנוּ בְאֵתָם בִּקְצֵה הַמִּדְבָּר׃
וַיהוָה הֹלֵךְ לִפְנֵיהֶם יוֹמָם בְּעַמּוּד עָנָן לַנְחֹתָם הַדֶּרֶךְ וְלַיְלָה בְּעַמּוּד אֵשׁ לְהָאִיר לָהֶם לָלֶכֶת יוֹמָם וָלָיְלָה׃
לֹא־יָמִישׁ עַמּוּד הֶעָנָן יוֹמָם וְעַמּוּד הָאֵשׁ לָיְלָה לִפְנֵי הָעָם׃

Chapter 14

וַיְדַבֵּר יְהֹוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְיָשֻׁבוּ וְיַחֲנוּ לִפְנֵי פִּי הַחִירֹת בֵּין מִגְדֹּל וּבֵין הַיָּם לִפְנֵי בַּעַל צְפֹן נִכְחוֹ תַחֲנוּ עַל־הַיָּם׃
וְאָמַר פַּרְעֹה לִבְנֵי יִשְׂרָאֵל נְבֻכִים הֵם בָּאָרֶץ סָגַר עֲלֵיהֶם הַמִּדְבָּר׃
וְחִזַּקְתִּי אֶת־לֵב־פַּרְעֹה וְרָדַף אַחֲרֵיהֶם וְאִכָּבְדָה בְּפַרְעֹה וּבְכָל־חֵילוֹ וְיָדְעוּ מִצְרַיִם כִּי־אֲנִי יְהוָה וַיַּעֲשׂוּ־כֵן׃
וַיֻּגַּד לְמֶלֶךְ מִצְרַיִם כִּי בָרַח הָעָם וַיֵּהָפֵךְ לְבַב פַּרְעֹה וַעֲבָדָיו אֶל־הָעָם וַיֹּאמרוּ מַה־זֹּאת עָשִׂינוּ כִּי־שִׁלַּחְנוּ אֶת־יִשְׂרָאֵל מֵעָבְדֵנוּ׃
וַיֶּאְסֹר אֶת־רִכְבּוֹ וְאֶת־עַמּוֹ לָקַח עִמּוֹ׃
וַיִּקַּח שֵׁשׁ־מֵאוֹת רֶכֶב בָּחוּר וְכֹל רֶכֶב מִצְרָיִם וְשָׁלִשִׁם עַל־כֻּלּוֹ׃
וַיְחַזֵּק יְהֹוָה אֶת־לֵב פַּרְעֹה מֶלֶךְ מִצְרַיִם וַיִּרְדֹּף אַחֲרֵי בְּנֵי יִשְׂרָאֵל וּבְנֵי יִשְׂרָאֵל יֹצְאִים בְּיָד רָמָה׃
וַיִּרְדְּפוּ מִצְרַיִם אַחֲרֵיהֶם וַיַּשִּׂיגוּ אוֹתָם חֹנִים עַל־הַיָּם כָּל־סוּס רֶכֶב פַּרְעֹה וּפָרָשָׁיו וְחֵילוֹ עַל־פִּי הַחִירֹת לִפְנֵי בַּעַל צְפֹן׃
וּפַרְעֹה הִקְרִיב וַיִּשְׂאוּ בְנֵי־יִשְׂרָאֵל אֶת־עֵינֵיהֶם וְהִנֵּה מִצְרַיִם נֹסֵעַ אַחֲרֵיהֶם וַיִּירְאוּ מְאֹד וַיִּצְעֲקוּ בְנֵי־יִשְׂרָאֵל אֶל־יְהוָה׃
וַיֹּאמְרוּ אֶל־מֹשֶׁה הַמִבְּלִי אֵין־קְבָרִים בְּמִצְרַיִם לְקַחְתָּנוּ לָמוּת בַּמִּדְבָּר מַה־זֹּאת עָשִׂיתָ לָּנוּ לְהוֹצִיאָנוּ מִמִּצְרָיִם׃
הֲלֹא־זֶה הַדָּבָר אֲשֶׁר דִּבַּרְנוּ אֵלֶיךָ בְמִצְרַיִם לֵאמֹר חֲדַל מִמֶּנּוּ וְנַעַבְדָה אֶת־מִצְרָיִם כִּי טוֹב לָנוּ עֲבֹד אֶת־מִצְרַיִם מִמֻּתֵנוּ בַּמִּדְבָּר׃
וַיֹּאמֶר מֹשֶׁה אֶל־הָעָם אַל־תִּירָאוּ הִתְיַצְבוּ וּרְאוּ אֶת־יְשׁוּעַת יְהוָה אֲשֶׁר־יַעֲשֶׂה לָכֶם הַיּוֹם כִּי אֲשֶׁר רְאִיתֶם אֶת־מִצְרַיִם הַיּוֹם לֹא תֹסִיפוּ לִרְאֹתָם עוֹד עַד־עוֹלָם׃
יְהוָה יִלָּחֵם לָכֶם וְאַתֶּם תַּחֲרִישׁוּן׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה מַה־תִּצְעַק אֵלָי דַּבֵּר אֶל־בְּנֵי־יִשְׂרָאֵל וְיִסָּעוּ׃
וְאַתָּה הָרֵם אֶת־מַטְּךָ וּנְטֵה אֶת־יָדְךָ עַל־הַיָּם וּבְקָעֵהוּ וְיָבֹאוּ בְנֵי־יִשְׂרָאֵל בְּתוֹךְ הַיָּם בַּיַּבָּשָׁה׃
וַאֲנִי הִנְנִי מְחַזֵּק אֶת־לֵב מִצְרַיִם וְיָבֹאוּ אַחֲרֵיהֶם וְאִכָּבְדָה בְּפַרְעֹה וּבְכָל־חֵילוֹ בְּרִכְבּוֹ וּבְפָרָשָׁיו׃
וְיָדְעוּ מִצְרַיִם כִּי־אֲנִי יְהוָה בְּהִכָּבְדִי בְּפַרְעֹה בְּרִכְבּוֹ וּבְפָרָשָׁיו׃
וַיִּסַּע מַלְאַךְ הָאֱלֹהִים הַהֹלֵךְ לִפְנֵי מַחֲנֵה יִשְׂרָאֵל וַיֵּלֶךְ מֵאַחֲרֵיהֶם וַיִּסַּע עַמּוּד הֶעָנָן מִפְּנֵיהֶם וַיַּעֲמֹד מֵאַחֲרֵיהֶם׃
וַיָּבֹא בֵּין מַחֲנֵה מִצְרַיִם וּבֵין מַחֲנֵה יִשְׂרָאֵל וַיְהִי הֶעָנָן וְהַחֹשֶׁךְ וַיָּאֶר אֶת־הַלָּיְלָה וְלֹא־קָרַב זֶה אֶל־זֶה כָּל־הַלָּיְלָה׃
וַיֵּט מֹשֶׁה אֶת־יָדוֹ עַל־הַיָּם וַיּוֹלֶךְ יְהוָה אֶת־הַיָּם בְּרוּחַ קָדִים עַזָּה כָּל־הַלַּיְלָה וַיָּשֶׂם אֶת־הַיָּם לֶחָרָבָה וַיִּבָּקְעוּ הַמָּיִם׃
וַיָּבֹאוּ בְנֵי־יִשְׂרָאֵל בְּתוֹךְ הַיָּם בַּיַּבָּשָׁה וְהַמַּיִם לָהֶם חֹמָה מִימִינָם וּמִשְּׂמֹאלָם׃
וַיִּרְדְּפוּ מִצְרַיִם וַיָּבֹאוּ אַחֲרֵיהֶם כֹּל סוּס פַּרְעֹה רִכְבּוֹ וּפָרָשָׁיו אֶל־תּוֹךְ הַיָּם׃
וַיְהִי בְּאַשְׁמֹרֶת הַבֹּקֶר וַיַּשְׁקֵף יְהוָה אֶל־מַחֲנֵה מִצְרַיִם בְּעַמּוּד אֵשׁ וְעָנָן וַיָּהָם אֵת מַחֲנֵה מִצְרָיִם׃
וַיָּסַר אֵת אֹפַן מַרְכְּבֹתָיו וַיְנַהֲגֵהוּ בִּכְבֵדֻת וַיֹּאמֶר מִצְרַיִם אָנוּסָה מִפְּנֵי יִשְׂרָאֵל כִּי יְהוָה נִלְחָם לָהֶם בְּמִצְרָיִם
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה נְטֵה אֶת־יָדְךָ עַל־הַיָּם וְיָשֻׁבוּ הַמַּיִם עַל־מִצְרַיִם עַל־רִכְבּוֹ וְעַל־פָּרָשָׁיו׃
וַיֵּט מֹשֶׁה אֶת־יָדוֹ עַל־הַיָּם וַיָּשָׁב הַיָּם לִפְנוֹת בֹּקֶר לְאֵיתָנוֹ וּמִצְרַיִם נָסִים לִקְרָאתוֹ וַיְנַעֵר יְהוָה אֶת־מִצְרַיִם בְּתוֹךְ הַיָּם׃
וַיָּשֻׁבוּ הַמַּיִם וַיְכַסּוּ אֶת־הָרֶכֶב וְאֶת־הַפָּרָשִׁים לְכֹל חֵיל פַּרְעֹה הַבָּאִים אַחֲרֵיהֶם בַּיָּם לֹא־נִשְׁאַר בָּהֶם עַד־אֶחָד׃
וּבְנֵי יִשְׂרָאֵל הָלְכוּ בַיַּבָּשָׁה בְּתוֹךְ הַיָּם וְהַמַּיִם לָהֶם חֹמָה מִימִינָם וּמִשְּׂמֹאלָם
וַיּוֹשַׁע יְהוָה בַּיּוֹם הַהוּא אֶת־יִשְׂרָאֵל מִיַּד מִצְרָיִם וַיַּרְא יִשְׂרָאֵל אֶת־מִצְרַיִם מֵת עַל־שְׂפַת הַיָּם׃
וַיַּרְא יִשְׂרָאֵל אֶת־הַיָּד הַגְּדֹלָה אֲשֶׁר עָשָׂה יְהוָה בְּמִצְרַיִם וַיִּירְאוּ הָעָם אֶת־יְהוָה וַיַּאֲמִינוּ בַּיהוָה וּבְמֹשֶׁה עַבְדּוֹ׃

Chapter 15

אָז יָשִׁיר־מֹשֶׁה וּבְנֵי יִשְׂרָאֵל אֶת־הַשִּׁירָה הַזֹּאת לַיהוָה וַיֹּאמְרוּ לֵאמֹר אָשִׁירָה לַיהוָה כִּי־גָאֹה גָּאָה סוּס וְרֹכְבוֹ רָמָה בַיָּם׃
עָזִּי וְזִמְרָת יָהּ וַיְהִי־לִי לִישׁוּעָה זֶה אֵלִי וְאַנְוֵהוּ אֱלֹהֵי אָבִי וַאֲרֹמְמֶנְהוּ׃
יְהוָה אִישׁ מִלְחָמָה יְהוָה שְׁמוֹ׃
מַרְכְּבֹת פַּרְעֹה וְחֵילוֹ יָרָה בַיָּם וּמִבְחַר שָׁלִשָׁיו טֻבְּעוּ בְיַם־סוּף׃
תְּהֹמֹת יְכַסְיֻמוּ יָרְדוּ בִמְצוֹלֹת כְּמוֹ־אָבֶן׃
יְמִינְךָ יְהוָה נֶאְדָּרִי בַּכֹּחַ יְמִינְךָ יְהוָה תִּרְעַץ אוֹיֵב׃
וּבְרֹב גְּאוֹנְךָ תַּהֲרֹס קָמֶיךָ תְּשַׁלַּח חֲרֹנְךָ יֹאכְלֵמוֹ כַּקַּשׁ׃
וּבְרוּחַ אַפֶּיךָ נֶעֶרְמוּ מַיִם נִצְּבוּ כְמוֹ־נֵד נֹזְלִים קָפְאוּ תְהֹמֹת בְּלֶב־יָם׃
אָמַר אוֹיֵב אֶרְדֹּף אַשִּׂיג אֲחַלֵּק שָׁלָל תִּמְלָאֵמוֹ נַפְשִׁי אָרִיק חַרְבִּי תּוֹרִישֵׁמוֹ יָדִי׃
נָשַׁפְתָּ בְרוּחֲךָ כִּסָּמוֹ יָם צָלֲלוּ כַּעוֹפֶרֶת בְּמַיִם אַדִּירִים׃
מִי־כָמֹכָה בָּאֵלִם יְהוָה מִי כָּמֹכָה נֶאְדָּר בַּקֹּדֶשׁ נוֹרָא תְהִלֹּת עֹשֵׂה פֶלֶא׃
נָטִיתָ יְמִינְךָ תִּבְלָעֵמוֹ אָרֶץ׃
נָחִיתָ בְחַסְדְּךָ עַם־זוּ גָּאָלְתָּ נֵהַלְתָּ בְעָזְּךָ אֶל־נְוֵה קָדְשֶׁךָ׃
שָׁמְעוּ עַמִּים יִרְגָּזוּן חִיל אָחַז יֹשְׁבֵי פְּלָשֶׁת׃
אָז נִבְהֲלוּ אַלּוּפֵי אֱדוֹם אֵילֵי מוֹאָב יֹאחֲזֵמוֹ רָעַד נָמֹגוּ כֹּל יֹשְׁבֵי כְנָעַן׃
תִּפֹּל עֲלֵיהֶם אֵימָתָה וָפַחַד בִּגְדֹל זְרוֹעֲךָ יִדְּמוּ כָּאָבֶן עַד־יַעֲבֹר עַמְּךָ יְהוָה עַד־יַעֲבֹר עַם־זוּ קָנִיתָ׃
תְּבִאֵמוֹ וְתִטָּעֵמוֹ בְּהַר נַחֲלָתְךָ מָכוֹן לְשִׁבְתְּךָ פָּעַלְתָּ יְהוָה מִקְּדָשׁ אֲדֹנָי כּוֹנְנוּ יָדֶיךָ׃
יְהוָה יִמְלֹךְ לְעֹלָם וָעֶד׃
כִּי בָא סוּס פַּרְעֹה בְּרִכְבּוֹ וּבְפָרָשָׁיו בַּיָּם וַיָּשֶׁב יְהוָה עֲלֵהֶם אֶת־מֵי הַיָּם וּבְנֵי יִשְׂרָאֵל הָלְכוּ בַיַּבָּשָׁה בְּתוֹךְ הַיָּם׃
וַתִּקַּח מִרְיָם הַנְּבִיאָה אֲחוֹת אַהֲרֹן אֶת־הַתֹּף בְּיָדָהּ וַתֵּצֶאןָ כָל־הַנָּשִׁים אַחֲרֶיהָ בְּתֻפִּים וּבִמְחֹלֹת׃
וַתַּעַן לָהֶם מִרְיָם שִׁירוּ לַיהוָה כִּי־גָאֹה גָּאָה סוּס וְרֹכְבוֹ רָמָה בַיָּם׃
וַיַּסַּע מֹשֶׁה אֶת־יִשְׂרָאֵל מִיַּם־סוּף וַיֵּצְאוּ אֶל־מִדְבַּר־שׁוּר וַיֵּלְכוּ שְׁלֹשֶׁת־יָמִים בַּמִּדְבָּר וְלֹא־מָצְאוּ מָיִם׃
וַיָּבֹאוּ מָרָתָה וְלֹא יָכְלוּ לִשְׁתֹּת מַיִם מִמָּרָה כִּי מָרִים הֵם עַל־כֵּן קָרָא־שְׁמָהּ מָרָה׃
וַיִּלֹּנוּ הָעָם עַל־מֹשֶׁה לֵּאמֹר מַה־נִּשְׁתֶּה׃
וַיִּצְעַק אֶל־יְהוָה וַיּוֹרֵהוּ יְהוָה עֵץ וַיַּשְׁלֵךְ אֶל־הַמַּיִם וַיִּמְתְּקוּ הַמָּיִם שָׁם שָׂם לוֹ חֹק וּמִשְׁפָּט וְשָׁם נִסָּהוּ׃
וַיֹּאמֶר אִם־שָׁמוֹעַ תִּשְׁמַע לְקוֹל יְהוָה אֱלֹהֶיךָ וְהַיָּשָׁר בְּעֵינָיו תַּעֲשֶׂה וְהַאֲזַנְתָּ לְמִצְוֺתָיו וְשָׁמַרְתָּ כָּל־חֻקָּיו כָּל־הַמַּחֲלָה אֲשֶׁר־שַׂמְתִּי בְמִצְרַיִם לֹא־אָשִׂים עָלֶיךָ כִּי אֲנִי יְהוָה רֹפְאֶךָ׃
וַיָּבֹאוּ אֵילִמָה וְשָׁם שְׁתֵּים עֶשְׂרֵה עֵינֹת מַיִם וְשִׁבְעִים תְּמָרִים וַיַּחֲנוּ־שָׁם עַל־הַמָּיִם׃

Chapter 16

וַיִּסְעוּ מֵאֵילִם וַיָּבֹאוּ כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל אֶל־מִדְבַּר־סִין אֲשֶׁר בֵּין־אֵילִם וּבֵין סִינָי בַּחֲמִשָּׁה עָשָׂר יוֹם לַחֹדֶשׁ הַשֵּׁנִי לְצֵאתָם מֵאֶרֶץ מִצְרָיִם׃
וילינו [וַיִּלּוֹנוּ] כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל עַל־מֹשֶׁה וְעַל־אַהֲרֹן בַּמִּדְבָּר׃
וַיֹּאמְרוּ אֲלֵהֶם בְּנֵי יִשְׂרָאֵל מִי־יִתֵּן מוּתֵנוּ בְיַד־יְהוָה בְּאֶרֶץ מִצְרַיִם בְּשִׁבְתֵּנוּ עַל־סִיר הַבָּשָׂר בְּאָכְלֵנוּ לֶחֶם לָשֹׂבַע כִּי־הוֹצֵאתֶם אֹתָנוּ אֶל־הַמִּדְבָּר הַזֶּה לְהָמִית אֶת־כָּל־הַקָּהָל הַזֶּה בָּרָעָב׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה הִנְנִי מַמְטִיר לָכֶם לֶחֶם מִן־הַשָּׁמָיִם וְיָצָא הָעָם וְלָקְטוּ דְּבַר־יוֹם בְּיוֹמוֹ לְמַעַן אֲנַסֶּנּוּ הֲיֵלֵךְ בְּתוֹרָתִי אִם־לֹא׃
וְהָיָה בַּיּוֹם הַשִּׁשִּׁי וְהֵכִינוּ אֵת אֲשֶׁר־יָבִיאוּ וְהָיָה מִשְׁנֶה עַל אֲשֶׁר־יִלְקְטוּ יוֹם יוֹם׃
וַיֹּאמֶר מֹשֶׁה וְאַהֲרֹן אֶל־כָּל־בְּנֵי יִשְׂרָאֵל עֶרֶב וִידַעְתֶּם כִּי יְהוָה הוֹצִיא אֶתְכֶם מֵאֶרֶץ מִצְרָיִם׃
וּבֹקֶר וּרְאִיתֶם אֶת־כְּבוֹד יְהוָה בְּשָׁמְעוֹ אֶת־תְּלֻנֹּתֵיכֶם עַל־יְהוָה וְנַחְנוּ מָה כִּי תלונו [תַלִּינוּ] עָלֵינוּ׃
וַיֹּאמֶר מֹשֶׁה בְּתֵת יְהוָה לָכֶם בָּעֶרֶב בָּשָׂר לֶאֱכֹל וְלֶחֶם בַּבֹּקֶר לִשְׂבֹּעַ בִּשְׁמֹעַ יְהוָה אֶת־תְּלֻנֹּתֵיכֶם אֲשֶׁר־אַתֶּם מַלִּינִם עָלָיו וְנַחְנוּ מָה לֹא־עָלֵינוּ תְלֻנֹּתֵיכֶם כִּי עַל־יְהוָה׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן אֱמֹר אֶל־כָּל־עֲדַת בְּנֵי יִשְׂרָאֵל קִרְבוּ לִפְנֵי יְהוָה כִּי שָׁמַע אֵת תְּלֻנֹּתֵיכֶם׃
וַיְהִי כְּדַבֵּר אַהֲרֹן אֶל־כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל וַיִּפְנוּ אֶל־הַמִּדְבָּר וְהִנֵּה כְּבוֹד יְהוָה נִרְאָה בֶּעָנָן׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
שָׁמַעְתִּי אֶת־תְּלוּנֹּת בְּנֵי יִשְׂרָאֵל דַּבֵּר אֲלֵהֶם לֵאמֹר בֵּין הָעַרְבַּיִם תֹּאכְלוּ בָשָׂר וּבַבֹּקֶר תִּשְׂבְּעוּ־לָחֶם וִידַעְתֶּם כִּי אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וַיְהִי בָעֶרֶב וַתַּעַל הַשְּׂלָו וַתְּכַס אֶת־הַמַּחֲנֶה וּבַבֹּקֶר הָיְתָה שִׁכְבַת הַטַּל סָבִיב לַמַּחֲנֶה׃
וַתַּעַל שִׁכְבַת הַטָּל וְהִנֵּה עַל־פְּנֵי הַמִּדְבָּר דַּק מְחֻסְפָּס דַּק כַּכְּפֹר עַל־הָאָרֶץ׃
וַיִּרְאוּ בְנֵי־יִשְׂרָאֵל וַיֹּאמְרוּ אִישׁ אֶל־אָחִיו מָן הוּא כִּי לֹא יָדְעוּ מַה־הוּא וַיֹּאמֶר מֹשֶׁה אֲלֵהֶם הוּא הַלֶּחֶם אֲשֶׁר נָתַן יְהוָה לָכֶם לְאָכְלָה׃
זֶה הַדָּבָר אֲשֶׁר צִוָּה יְהוָה לִקְטוּ מִמֶּנּוּ אִישׁ לְפִי אָכְלוֹ עֹמֶר לַגֻּלְגֹּלֶת מִסְפַּר נַפְשֹׁתֵיכֶם אִישׁ לַאֲשֶׁר בְּאָהֳלוֹ תִּקָּחוּ׃
וַיַּעֲשׂוּ־כֵן בְּנֵי יִשְׂרָאֵל וַיִּלְקְטוּ הַמַּרְבֶּה וְהַמַּמְעִיט׃
וַיָּמֹדּוּ בָעֹמֶר וְלֹא הֶעְדִּיף הַמַּרְבֶּה וְהַמַּמְעִיט לֹא הֶחְסִיר אִישׁ לְפִי־אָכְלוֹ לָקָטוּ׃
וַיֹּאמֶר מֹשֶׁה אֲלֵהֶם אִישׁ אַל־יוֹתֵר מִמֶּנּוּ עַד־בֹּקֶר׃
וְלֹא־שָׁמְעוּ אֶל־מֹשֶׁה וַיּוֹתִרוּ אֲנָשִׁים מִמֶּנּוּ עַד־בֹּקֶר וַיָּרֻם תּוֹלָעִים וַיִּבְאַשׁ וַיִּקְצֹף עֲלֵהֶם מֹשֶׁה׃
וַיִּלְקְטוּ אֹתוֹ בַּבֹּקֶר בַּבֹּקֶר אִישׁ כְּפִי אָכְלוֹ וְחַם הַשֶּׁמֶשׁ וְנָמָס׃
וַיְהִי בַּיּוֹם הַשִּׁשִּׁי לָקְטוּ לֶחֶם מִשְׁנֶה שְׁנֵי הָעֹמֶר לָאֶחָד וַיָּבֹאוּ כָּל־נְשִׂיאֵי הָעֵדָה וַיַּגִּידוּ לְמֹשֶׁה׃
וַיֹּאמֶר אֲלֵהֶם הוּא אֲשֶׁר דִּבֶּר יְהוָה שַׁבָּתוֹן שַׁבַּת־קֹדֶשׁ לַיהוָה מָחָר אֵת אֲשֶׁר־תֹּאפוּ אֵפוּ וְאֵת אֲשֶׁר־תְּבַשְּׁלוּ בַּשֵּׁלוּ וְאֵת כָּל־הָעֹדֵף הַנִּיחוּ לָכֶם לְמִשְׁמֶרֶת עַד־הַבֹּקֶר׃
וַיַּנִּיחוּ אֹתוֹ עַד־הַבֹּקֶר כַּאֲשֶׁר צִוָּה מֹשֶׁה וְלֹא הִבְאִישׁ וְרִמָּה לֹא־הָיְתָה בּוֹ׃
וַיֹּאמֶר מֹשֶׁה אִכְלֻהוּ הַיּוֹם כִּי־שַׁבָּת הַיּוֹם לַיהוָה הַיּוֹם לֹא תִמְצָאֻהוּ בַּשָּׂדֶה׃
שֵׁשֶׁת יָמִים תִּלְקְטֻהוּ וּבַיּוֹם הַשְּׁבִיעִי שַׁבָּת לֹא יִהְיֶה־בּוֹ׃
וַיְהִי בַּיּוֹם הַשְּׁבִיעִי יָצְאוּ מִן־הָעָם לִלְקֹט וְלֹא מָצָאוּ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עַד־אָנָה מֵאַנְתֶּם לִשְׁמֹר מִצְוֺתַי וְתוֹרֹתָי׃
רְאוּ כִּי־יְהוָה נָתַן לָכֶם הַשַּׁבָּת עַל־כֵּן הוּא נֹתֵן לָכֶם בַּיּוֹם הַשִּׁשִּׁי לֶחֶם יוֹמָיִם שְׁבוּ אִישׁ תַּחְתָּיו אַל־יֵצֵא אִישׁ מִמְּקֹמוֹ בַּיּוֹם הַשְּׁבִיעִי׃
וַיִּשְׁבְּתוּ הָעָם בַּיּוֹם הַשְּׁבִעִי׃
וַיִּקְרְאוּ בֵית־יִשְׂרָאֵל אֶת־שְׁמוֹ מָן וְהוּא כְּזֶרַע גַּד לָבָן וְטַעְמוֹ כְּצַפִּיחִת בִּדְבָשׁ׃
וַיֹּאמֶר מֹשֶׁה זֶה הַדָּבָר אֲשֶׁר צִוָּה יְהוָה מְלֹא הָעֹמֶר מִמֶּנּוּ לְמִשְׁמֶרֶת לְדֹרֹתֵיכֶם לְמַעַן יִרְאוּ אֶת־הַלֶּחֶם אֲשֶׁר הֶאֱכַלְתִּי אֶתְכֶם בַּמִּדְבָּר בְּהוֹצִיאִי אֶתְכֶם מֵאֶרֶץ מִצְרָיִם׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן קַח צִנְצֶנֶת אַחַת וְתֶן־שָׁמָּה מְלֹא־הָעֹמֶר מָן וְהַנַּח אֹתוֹ לִפְנֵי יְהוָה לְמִשְׁמֶרֶת לְדֹרֹתֵיכֶם׃
כַּאֲשֶׁר צִוָּה יְהוָה אֶל־מֹשֶׁה וַיַּנִּיחֵהוּ אַהֲרֹן לִפְנֵי הָעֵדֻת לְמִשְׁמָרֶת׃
וּבְנֵי יִשְׂרָאֵל אָכְלוּ אֶת־הַמָּן אַרְבָּעִים שָׁנָה עַד־בֹּאָם אֶל־אֶרֶץ נוֹשָׁבֶת אֶת־הַמָּן אָכְלוּ עַד־בֹּאָם אֶל־קְצֵה אֶרֶץ כְּנָעַן׃
וְהָעֹמֶר עֲשִׂרִית הָאֵיפָה הוּא׃

Chapter 17

וַיִּסְעוּ כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל מִמִּדְבַּר־סִין לְמַסְעֵיהֶם עַל־פִּי יְהוָה וַיַּחֲנוּ בִּרְפִידִים וְאֵין מַיִם לִשְׁתֹּת הָעָם׃
וַיָּרֶב הָעָם עִם־מֹשֶׁה וַיֹּאמְרוּ תְּנוּ־לָנוּ מַיִם וְנִשְׁתֶּה וַיֹּאמֶר לָהֶם מֹשֶׁה מַה־תְּרִיבוּן עִמָּדִי מַה־תְּנַסּוּן אֶת־יְהוָה׃
וַיִּצְמָא שָׁם הָעָם לַמַּיִם וַיָּלֶן הָעָם עַל־מֹשֶׁה וַיֹּאמֶר לָמָּה זֶּה הֶעֱלִיתָנוּ מִמִּצְרַיִם לְהָמִית אֹתִי וְאֶת־בָּנַי וְאֶת־מִקְנַי בַּצָּמָא׃
וַיִּצְעַק מֹשֶׁה אֶל־יְהוָה לֵאמֹר מָה אֶעֱשֶׂה לָעָם הַזֶּה עוֹד מְעַט וּסְקָלֻנִי׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עֲבֹר לִפְנֵי הָעָם וְקַח אִתְּךָ מִזִּקְנֵי יִשְׂרָאֵל וּמַטְּךָ אֲשֶׁר הִכִּיתָ בּוֹ אֶת־הַיְאֹר קַח בְּיָדְךָ וְהָלָכְתָּ׃
הִנְנִי עֹמֵד לְפָנֶיךָ שָּׁם עַל־הַצּוּר בְּחֹרֵב וְהִכִּיתָ בַצּוּר וְיָצְאוּ מִמֶּנּוּ מַיִם וְשָׁתָה הָעָם וַיַּעַשׂ כֵּן מֹשֶׁה לְעֵינֵי זִקְנֵי יִשְׂרָאֵל׃
וַיִּקְרָא שֵׁם הַמָּקוֹם מַסָּה וּמְרִיבָה עַל־רִיב בְּנֵי יִשְׂרָאֵל וְעַל נַסֹּתָם אֶת־יְהוָה לֵאמֹר הֲיֵשׁ יְהוָה בְּקִרְבֵּנוּ אִם־אָיִן׃
וַיָּבֹא עֲמָלֵק וַיִּלָּחֶם עִם־יִשְׂרָאֵל בִּרְפִידִם׃
וַיֹּאמֶר מֹשֶׁה אֶל־יְהוֹשֻׁעַ בְּחַר־לָנוּ אֲנָשִׁים וְצֵא הִלָּחֵם בַּעֲמָלֵק מָחָר אָנֹכִי נִצָּב עַל־רֹאשׁ הַגִּבְעָה וּמַטֵּה הָאֱלֹהִים בְּיָדִי׃
וַיַּעַשׂ יְהוֹשֻׁעַ כַּאֲשֶׁר אָמַר־לוֹ מֹשֶׁה לְהִלָּחֵם בַּעֲמָלֵק וּמֹשֶׁה אַהֲרֹן וְחוּר עָלוּ רֹאשׁ הַגִּבְעָה׃
וְהָיָה כַּאֲשֶׁר יָרִים מֹשֶׁה יָדוֹ וְגָבַר יִשְׂרָאֵל וְכַאֲשֶׁר יָנִיחַ יָדוֹ וְגָבַר עֲמָלֵק׃
וִידֵי מֹשֶׁה כְּבֵדִים וַיִּקְחוּ־אֶבֶן וַיָּשִׂימוּ תַחְתָּיו וַיֵּשֶׁב עָלֶיהָ וְאַהֲרֹן וְחוּר תָּמְכוּ בְיָדָיו מִזֶּה אֶחָד וּמִזֶּה אֶחָד וַיְהִי יָדָיו אֱמוּנָה עַד־בֹּא הַשָּׁמֶשׁ׃
וַיַּחֲלֹשׁ יְהוֹשֻׁעַ אֶת־עֲמָלֵק וְאֶת־עַמּוֹ לְפִי־חָרֶב׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה כְּתֹב זֹאת זִכָּרוֹן בַּסֵּפֶר וְשִׂים בְּאָזְנֵי יְהוֹשֻׁעַ כִּי־מָחֹה אֶמְחֶה אֶת־זֵכֶר עֲמָלֵק מִתַּחַת הַשָּׁמָיִם׃
וַיִּבֶן מֹשֶׁה מִזְבֵּחַ וַיִּקְרָא שְׁמוֹ יְהוָה נִסִּי׃
וַיֹּאמֶר כִּי־יָד עַל־כֵּס יָהּ מִלְחָמָה לַיהוָה בַּעֲמָלֵק מִדֹּר דֹּר׃

Chapter 18

וַיִּשְׁמַע יִתְרוֹ כֹהֵן מִדְיָן חֹתֵן מֹשֶׁה אֵת כָּל־אֲשֶׁר עָשָׂה אֱלֹהִים לְמֹשֶׁה וּלְיִשְׂרָאֵל עַמּוֹ כִּי־הוֹצִיא יְהוָה אֶת־יִשְׂרָאֵל מִמִּצְרָיִם׃
וַיִּקַּח יִתְרוֹ חֹתֵן מֹשֶׁה אֶת־צִפֹּרָה אֵשֶׁת מֹשֶׁה אַחַר שִׁלּוּחֶיהָ׃
וְאֵת שְׁנֵי בָנֶיהָ אֲשֶׁר שֵׁם הָאֶחָד גֵּרְשֹׁם כִּי אָמַר גֵּר הָיִיתִי בְּאֶרֶץ נָכְרִיָּה׃
וְשֵׁם הָאֶחָד אֱלִיעֶזֶר כִּי־אֱלֹהֵי אָבִי בְּעֶזְרִי וַיַּצִּלֵנִי מֵחֶרֶב פַּרְעֹה׃
וַיָּבֹא יִתְרוֹ חֹתֵן מֹשֶׁה וּבָנָיו וְאִשְׁתּוֹ אֶל־מֹשֶׁה אֶל־הַמִּדְבָּר אֲשֶׁר־הוּא חֹנֶה שָׁם הַר הָאֱלֹהִים׃
וַיֹּאמֶר אֶל־מֹשֶׁה אֲנִי חֹתֶנְךָ יִתְרוֹ בָּא אֵלֶיךָ וְאִשְׁתְּךָ וּשְׁנֵי בָנֶיהָ עִמָּהּ׃
וַיֵּצֵא מֹשֶׁה לִקְרַאת חֹתְנוֹ וַיִּשְׁתַּחוּ וַיִּשַּׁק־לוֹ וַיִּשְׁאֲלוּ אִישׁ־לְרֵעֵהוּ לְשָׁלוֹם וַיָּבֹאוּ הָאֹהֱלָה׃
וַיְסַפֵּר מֹשֶׁה לְחֹתְנוֹ אֵת כָּל־אֲשֶׁר עָשָׂה יְהוָה לְפַרְעֹה וּלְמִצְרַיִם עַל אוֹדֹת יִשְׂרָאֵל אֵת כָּל־הַתְּלָאָה אֲשֶׁר מְצָאָתַם בַּדֶּרֶךְ וַיַּצִּלֵם יְהוָה׃
וַיִּחַדְּ יִתְרוֹ עַל כָּל־הַטּוֹבָה אֲשֶׁר־עָשָׂה יְהוָה לְיִשְׂרָאֵל אֲשֶׁר הִצִּילוֹ מִיַּד מִצְרָיִם׃
וַיֹּאמֶר יִתְרוֹ בָּרוּךְ יְהוָה אֲשֶׁר הִצִּיל אֶתְכֶם מִיַּד מִצְרַיִם וּמִיַּד פַּרְעֹה אֲשֶׁר הִצִּיל אֶת־הָעָם מִתַּחַת יַד־מִצְרָיִם׃
עַתָּה יָדַעְתִּי כִּי־גָדוֹל יְהוָה מִכָּל־הָאֱלֹהִים כִּי בַדָּבָר אֲשֶׁר זָדוּ עֲלֵיהֶם׃
וַיִּקַּח יִתְרוֹ חֹתֵן מֹשֶׁה עֹלָה וּזְבָחִים לֵאלֹהִים וַיָּבֹא אַהֲרֹן וְכֹל זִקְנֵי יִשְׂרָאֵל לֶאֱכָל־לֶחֶם עִם־חֹתֵן מֹשֶׁה לִפְנֵי הָאֱלֹהִים׃
וַיְהִי מִמָּחֳרָת וַיֵּשֶׁב מֹשֶׁה לִשְׁפֹּט אֶת־הָעָם וַיַּעֲמֹד הָעָם עַל־מֹשֶׁה מִן־הַבֹּקֶר עַד־הָעָרֶב׃
וַיַּרְא חֹתֵן מֹשֶׁה אֵת כָּל־אֲשֶׁר־הוּא עֹשֶׂה לָעָם וַיֹּאמֶר מָה־הַדָּבָר הַזֶּה אֲשֶׁר אַתָּה עֹשֶׂה לָעָם מַדּוּעַ אַתָּה יוֹשֵׁב לְבַדֶּךָ וְכָל־הָעָם נִצָּב עָלֶיךָ מִן־בֹּקֶר עַד־עָרֶב׃
וַיֹּאמֶר מֹשֶׁה לְחֹתְנוֹ כִּי־יָבֹא אֵלַי הָעָם לִדְרֹשׁ אֱלֹהִים׃
כִּי־יִהְיֶה לָהֶם דָּבָר בָּא אֵלַי וְשָׁפַטְתִּי בֵּין אִישׁ וּבֵין רֵעֵהוּ וְהוֹדַעְתִּי אֶת־חֻקֵּי הָאֱלֹהִים וְאֶת־תּוֹרֹתָיו׃
וַיֹּאמֶר חֹתֵן מֹשֶׁה אֵלָיו לֹא־טוֹב הַדָּבָר אֲשֶׁר אַתָּה עֹשֶׂה׃
נָבֹל תִּבֹּל גַּם־אַתָּה גַּם־הָעָם הַזֶּה אֲשֶׁר עִמָּךְ כִּי־כָבֵד מִמְּךָ הַדָּבָר לֹא־תוּכַל עֲשֹׂהוּ לְבַדֶּךָ׃
עַתָּה שְׁמַע בְּקֹלִי אִיעָצְךָ וִיהִי אֱלֹהִים עִמָּךְ הֱיֵה אַתָּה לָעָם מוּל הָאֱלֹהִים וְהֵבֵאתָ אַתָּה אֶת־הַדְּבָרִים אֶל־הָאֱלֹהִים׃
וְהִזְהַרְתָּה אֶתְהֶם אֶת־הַחֻקִּים וְאֶת־הַתּוֹרֹת וְהוֹדַעְתָּ לָהֶם אֶת־הַדֶּרֶךְ יֵלְכוּ בָהּ וְאֶת־הַמַּעֲשֶׂה אֲשֶׁר יַעֲשׂוּן׃
וְאַתָּה תֶחֱזֶה מִכָּל־הָעָם אַנְשֵׁי־חַיִל יִרְאֵי אֱלֹהִים אַנְשֵׁי אֱמֶת שֹׂנְאֵי בָצַע וְשַׂמְתָּ עֲלֵהֶם שָׂרֵי אֲלָפִים שָׂרֵי מֵאוֹת שָׂרֵי חֲמִשִּׁים וְשָׂרֵי עֲשָׂרֹת׃
וְשָׁפְטוּ אֶת־הָעָם בְּכָל־עֵת וְהָיָה כָּל־הַדָּבָר הַגָּדֹל יָבִיאוּ אֵלֶיךָ וְכָל־הַדָּבָר הַקָּטֹן יִשְׁפְּטוּ־הֵם וְהָקֵל מֵעָלֶיךָ וְנָשְׂאוּ אִתָּךְ׃
אִם אֶת־הַדָּבָר הַזֶּה תַּעֲשֶׂה וְצִוְּךָ אֱלֹהִים וְיָכָלְתָּ עֲמֹד וְגַם כָּל־הָעָם הַזֶּה עַל־מְקֹמוֹ יָבֹא בְשָׁלוֹם׃
וַיִּשְׁמַע מֹשֶׁה לְקוֹל חֹתְנוֹ וַיַּעַשׂ כֹּל אֲשֶׁר אָמָר׃
וַיִּבְחַר מֹשֶׁה אַנְשֵׁי־חַיִל מִכָּל־יִשְׂרָאֵל וַיִּתֵּן אֹתָם רָאשִׁים עַל־הָעָם שָׂרֵי אֲלָפִים שָׂרֵי מֵאוֹת שָׂרֵי חֲמִשִּׁים וְשָׂרֵי עֲשָׂרֹת׃
וְשָׁפְטוּ אֶת־הָעָם בְּכָל־עֵת אֶת־הַדָּבָר הַקָּשֶׁה יְבִיאוּן אֶל־מֹשֶׁה וְכָל־הַדָּבָר הַקָּטֹן יִשְׁפּוּטוּ הֵם׃
וַיְשַׁלַּח מֹשֶׁה אֶת־חֹתְנוֹ וַיֵּלֶךְ לוֹ אֶל־אַרְצוֹ׃

Chapter 19

בַּחֹדֶשׁ הַשְּׁלִישִׁי לְצֵאת בְּנֵי־יִשְׂרָאֵל מֵאֶרֶץ מִצְרָיִם בַּיּוֹם הַזֶּה בָּאוּ מִדְבַּר סִינָי׃
וַיִּסְעוּ מֵרְפִידִים וַיָּבֹאוּ מִדְבַּר סִינַי וַיַּחֲנוּ בַּמִּדְבָּר וַיִּחַן־שָׁם יִשְׂרָאֵל נֶגֶד הָהָר׃
וּמֹשֶׁה עָלָה אֶל־הָאֱלֹהִים וַיִּקְרָא אֵלָיו יְהוָה מִן־הָהָר לֵאמֹר כֹּה תֹאמַר לְבֵית יַעֲקֹב וְתַגֵּיד לִבְנֵי יִשְׂרָאֵל׃
אַתֶּם רְאִיתֶם אֲשֶׁר עָשִׂיתִי לְמִצְרָיִם וָאֶשָּׂא אֶתְכֶם עַל־כַּנְפֵי נְשָׁרִים וָאָבִא אֶתְכֶם אֵלָי׃
וְעַתָּה אִם־שָׁמוֹעַ תִּשְׁמְעוּ בְּקֹלִי וּשְׁמַרְתֶּם אֶת־בְּרִיתִי וִהְיִיתֶם לִי סְגֻלָּה מִכָּל־הָעַמִּים כִּי־לִי כָּל־הָאָרֶץ׃
וְאַתֶּם תִּהְיוּ־לִי מַמְלֶכֶת כֹּהֲנִים וְגוֹי קָדוֹשׁ אֵלֶּה הַדְּבָרִים אֲשֶׁר תְּדַבֵּר אֶל־בְּנֵי יִשְׂרָאֵל׃
וַיָּבֹא מֹשֶׁה וַיִּקְרָא לְזִקְנֵי הָעָם וַיָּשֶׂם לִפְנֵיהֶם אֵת כָּל־הַדְּבָרִים הָאֵלֶּה אֲשֶׁר צִוָּהוּ יְהוָה׃
וַיַּעֲנוּ כָל־הָעָם יַחְדָּו וַיֹּאמְרוּ כֹּל אֲשֶׁר־דִּבֶּר יְהוָה נַעֲשֶׂה וַיָּשֶׁב מֹשֶׁה אֶת־דִּבְרֵי הָעָם אֶל־יְהוָה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה הִנֵּה אָנֹכִי בָּא אֵלֶיךָ בְּעַב הֶעָנָן בַּעֲבוּר יִשְׁמַע הָעָם בְּדַבְּרִי עִמָּךְ וְגַם־בְּךָ יַאֲמִינוּ לְעוֹלָם וַיַּגֵּד מֹשֶׁה אֶת־דִּבְרֵי הָעָם אֶל־יְהוָה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה לֵךְ אֶל־הָעָם וְקִדַּשְׁתָּם הַיּוֹם וּמָחָר וְכִבְּסוּ שִׂמְלֹתָם׃
וְהָיוּ נְכֹנִים לַיּוֹם הַשְּׁלִישִׁי כִּי בַּיּוֹם הַשְּׁלִישִׁי יֵרֵד יְהוָה לְעֵינֵי כָל־הָעָם עַל־הַר סִינָי׃
וְהִגְבַּלְתָּ אֶת־הָעָם סָבִיב לֵאמֹר הִשָּׁמְרוּ לָכֶם עֲלוֹת בָּהָר וּנְגֹעַ בְּקָצֵהוּ כָּל־הַנֹּגֵעַ בָּהָר מוֹת יוּמָת׃
לֹא־תִגַּע בּוֹ יָד כִּי־סָקוֹל יִסָּקֵל אוֹ־יָרֹה יִיָּרֶה אִם־בְּהֵמָה אִם־אִישׁ לֹא יִחְיֶה בִּמְשֹׁךְ הַיֹּבֵל הֵמָּה יַעֲלוּ בָהָר׃
וַיֵּרֶד מֹשֶׁה מִן־הָהָר אֶל־הָעָם וַיְקַדֵּשׁ אֶת־הָעָם וַיְכַבְּסוּ שִׂמְלֹתָם׃
וַיֹּאמֶר אֶל־הָעָם הֱיוּ נְכֹנִים לִשְׁלֹשֶׁת יָמִים אַל־תִּגְּשׁוּ אֶל־אִשָּׁה׃
וַיְהִי בַיּוֹם הַשְּׁלִישִׁי בִּהְיֹת הַבֹּקֶר וַיְהִי קֹלֹת וּבְרָקִים וְעָנָן כָּבֵד עַל־הָהָר וְקֹל שֹׁפָר חָזָק מְאֹד וַיֶּחֱרַד כָּל־הָעָם אֲשֶׁר בַּמַּחֲנֶה׃
וַיּוֹצֵא מֹשֶׁה אֶת־הָעָם לִקְרַאת הָאֱלֹהִים מִן־הַמַּחֲנֶה וַיִּתְיַצְּבוּ בְּתַחְתִּית הָהָר׃
וְהַר סִינַי עָשַׁן כֻּלּוֹ מִפְּנֵי אֲשֶׁר יָרַד עָלָיו יְהוָה בָּאֵשׁ וַיַּעַל עֲשָׁנוֹ כְּעֶשֶׁן הַכִּבְשָׁן וַיֶּחֱרַד כָּל־הָהָר מְאֹד׃
וַיְהִי קוֹל הַשּׁוֹפָר הוֹלֵךְ וְחָזֵק מְאֹד מֹשֶׁה יְדַבֵּר וְהָאֱלֹהִים יַעֲנֶנּוּ בְקוֹל׃
וַיֵּרֶד יְהוָה עַל־הַר סִינַי אֶל־רֹאשׁ הָהָר וַיִּקְרָא יְהוָה לְמֹשֶׁה אֶל־רֹאשׁ הָהָר וַיַּעַל מֹשֶׁה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה רֵד הָעֵד בָּעָם פֶּן־יֶהֶרְסוּ אֶל־יְהוָה לִרְאוֹת וְנָפַל מִמֶּנּוּ רָב׃
וְגַם הַכֹּהֲנִים הַנִּגָּשִׁים אֶל־יְהוָה יִתְקַדָּשׁוּ פֶּן־יִפְרֹץ בָּהֶם יְהוָה׃
וַיֹּאמֶר מֹשֶׁה אֶל־יְהוָה לֹא־יוּכַל הָעָם לַעֲלֹת אֶל־הַר סִינָי כִּי־אַתָּה הַעֵדֹתָה בָּנוּ לֵאמֹר הַגְבֵּל אֶת־הָהָר וְקִדַּשְׁתּוֹ׃
וַיֹּאמֶר אֵלָיו יְהוָה לֶךְ־רֵד וְעָלִיתָ אַתָּה וְאַהֲרֹן עִמָּךְ וְהַכֹּהֲנִים וְהָעָם אַל־יֶהֶרְסוּ לַעֲלֹת אֶל־יְהוָה פֶּן־יִפְרָץ־בָּם׃
וַיֵּרֶד מֹשֶׁה אֶל־הָעָם וַיֹּאמֶר אֲלֵהֶם׃

Chapter 20

וַיְדַבֵּר אֱלֹהִים אֵת כָּל־הַדְּבָרִים הָאֵלֶּה לֵאמֹר׃
אָנֹכִי יְהוָה אֱלֹהֶיךָ אֲשֶׁר הוֹצֵאתִיךָ מֵאֶרֶץ מִצְרַיִם מִבֵּית עֲבָדִים׃
לֹא יִהְיֶה־לְךָ אֱלֹהִים אֲחֵרִים עַל־פָּנָיַ
לֹא תַעֲשֶׂה־לְךָ פֶסֶל וְכָל־תְּמוּנָה אֲשֶׁר בַּשָּׁמַיִם מִמַּעַל וַאֲשֶׁר בָּאָרֶץ מִתַָּחַת וַאֲשֶׁר בַּמַּיִם מִתַּחַת לָאָרֶץ
לֹא־תִשְׁתַּחְוֶה לָהֶם וְלֹא תָעָבְדֵם כִּי אָנֹכִי יְהוָה אֱלֹהֶיךָ אֵל קַנָּא פֹּקֵד עֲוֺן אָבֹת עַל־בָּנִים עַל־שִׁלֵּשִׁים וְעַל־רִבֵּעִים לְשֹׂנְאָי׃
וְעֹשֶׂה חֶסֶד לַאֲלָפִים לְאֹהֲבַי וּלְשֹׁמְרֵי מִצְוֺתָי׃
לֹא תִשָּׂא אֶת־שֵׁם־יְהוָה אֱלֹהֶיךָ לַשָּׁוְא כִּי לֹא יְנַקֶּה יְהוָה אֵת אֲשֶׁר־יִשָּׂא אֶת־שְׁמוֹ לַשָּׁוְא׃
זָכוֹר אֶת־יוֹם הַשַּׁבָּת לְקַדְּשׁוֹ
שֵׁשֶׁת יָמִים תַּעֲבֹד וְעָשִׂיתָ כָּל־מְלַאכְתֶּךָ
וְיוֹם הַשְּׁבִיעִי שַׁבָּת לַיהוָה אֱלֹהֶיךָ לֹא־תַעֲשֶׂה כָל־מְלָאכָה אַתָּה וּבִנְךָ־וּבִתֶּךָ עַבְדְּךָ וַאֲמָתְךָ וּבְהֶמְתֶּךָ וְגֵרְךָ אֲשֶׁר בִּשְׁעָרֶיךָ
כִּי שֵׁשֶׁת־יָמִים עָשָׂה יְהוָה אֶת־הַשָּׁמַיִם וְאֶת־הָאָרֶץ אֶת־הַיָּם וְאֶת־כָּל־אֲשֶׁר־בָּם וַיָּנַח בַּיּוֹם הַשְּׁבִיעִי עַל־כֵּן בֵּרַךְ יְהוָה אֶת־יוֹם הַשַּׁבָּת וַיְקַדְּשֵׁהוּ׃
כַּבֵּד אֶת־אָבִיךָ וְאֶת־אִמֶּךָ לְמַעַן יַאֲרִכוּן יָמֶיךָ עַל הָאֲדָמָה אֲשֶׁר־יְהוָה אֱלֹהֶיךָ נֹתֵן לָךְ׃
לֹא תִּרְצָח׃ לֹא תִּנְאָף׃ לֹא תִּגְנֹב׃ לֹא־תַעֲנֶה בְרֵעֲךָ עֵד שָׁקֶר׃
לֹא תַחְמֹד בֵּית רֵעֶךָ לֹא־תַחְמֹד אֵשֶׁת רֵעֶךָ וְעַבְדּוֹ וַאֲמָתוֹ וְשׁוֹרוֹ וַחֲמֹרוֹ וְכֹל אֲשֶׁר לְרֵעֶךָ׃
וְכָל־הָעָם רֹאִים אֶת־הַקּוֹלֹת וְאֶת־הַלַּפִּידִם וְאֵת קוֹל הַשֹּׁפָר וְאֶת־הָהָר עָשֵׁן וַיַּרְא הָעָם וַיָּנֻעוּ וַיַּעַמְדוּ מֵרָחֹק׃
וַיֹּאמְרוּ אֶל־מֹשֶׁה דַּבֵּר־אַתָּה עִמָּנוּ וְנִשְׁמָעָה וְאַל־יְדַבֵּר עִמָּנוּ אֱלֹהִים פֶּן־נָמוּת׃
וַיֹּאמֶר מֹשֶׁה אֶל־הָעָם אַל־תִּירָאוּ כִּי לְבַעֲבוּר נַסּוֹת אֶתְכֶם בָּא הָאֱלֹהִים וּבַעֲבוּר תִּהְיֶה יִרְאָתוֹ עַל־פְּנֵיכֶם לְבִלְתִּי תֶחֱטָאוּ׃
וַיַּעֲמֹד הָעָם מֵרָחֹק וּמֹשֶׁה נִגַּשׁ אֶל־הָעֲרָפֶל אֲשֶׁר־שָׁם הָאֱלֹהִים׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה כֹּה תֹאמַר אֶל־בְּנֵי יִשְׂרָאֵל אַתֶּם רְאִיתֶם כִּי מִן־הַשָּׁמַיִם דִּבַּרְתִּי עִמָּכֶם׃
לֹא תַעֲשׂוּן אִתִּי אֱלֹהֵי כֶסֶף וֵאלֹהֵי זָהָב לֹא תַעֲשׂוּ לָכֶם׃
מִזְבַּח אֲדָמָה תַּעֲשֶׂה־לִּי וְזָבַחְתָּ עָלָיו אֶת־עֹלֹתֶיךָ וְאֶת־שְׁלָמֶיךָ אֶת־צֹאנְךָ וְאֶת־בְּקָרֶךָ בְּכָל־הַמָּקוֹם אֲשֶׁר אַזְכִּיר אֶת־שְׁמִי אָבוֹא אֵלֶיךָ וּבֵרַכְתִּיךָ׃
וְאִם־מִזְבַּח אֲבָנִים תַּעֲשֶׂה־לִּי לֹא־תִבְנֶה אֶתְהֶן גָּזִית כִּי חַרְבְּךָ הֵנַפְתָּ עָלֶיהָ וַתְּחַלְלֶהָ׃
וְלֹא־תַעֲלֶה בְמַעֲלֹת עַל־מִזְבְּחִי אֲשֶׁר לֹא־תִגָּלֶה עֶרְוָתְךָ עָלָיו׃

Chapter 21

וְאֵלֶּה הַמִּשְׁפָּטִים אֲשֶׁר תָּשִׂים לִפְנֵיהֶם׃
כִּי תִקְנֶה עֶבֶד עִבְרִי שֵׁשׁ שָׁנִים יַעֲבֹד וּבַשְּׁבִעִת יֵצֵא לַחָפְשִׁי חִנָּם׃
אִם־בְּגַפּוֹ יָבֹא בְּגַפּוֹ יֵצֵא אִם־בַּעַל אִשָּׁה הוּא וְיָצְאָה אִשְׁתּוֹ עִמּוֹ׃
אִם־אֲדֹנָיו יִתֶּן־לוֹ אִשָּׁה וְיָלְדָה־לוֹ בָנִים אוֹ בָנוֹת הָאִשָּׁה וִילָדֶיהָ תִּהְיֶה לַאדֹנֶיהָ וְהוּא יֵצֵא בְגַפּוֹ׃
וְאִם־אָמֹר יֹאמַר הָעֶבֶד אָהַבְתִּי אֶת־אֲדֹנִי אֶת־אִשְׁתִּי וְאֶת־בָּנָי לֹא אֵצֵא חָפְשִׁי׃
וְהִגִּישׁוֹ אֲדֹנָיו אֶל־הָאֱלֹהִים וְהִגִּישׁוֹ אֶל־הַדֶּלֶת אוֹ אֶל־הַמְּזוּזָה וְרָצַע אֲדֹנָיו אֶת־אָזְנוֹ בַּמַּרְצֵעַ וַעֲבָדוֹ לְעֹלָם׃
וְכִי־יִמְכֹּר אִישׁ אֶת־בִּתּוֹ לְאָמָה לֹא תֵצֵא כְּצֵאת הָעֲבָדִים׃
אִם־רָעָה בְּעֵינֵי אֲדֹנֶיהָ אֲשֶׁר־לא [לוֹ] יְעָדָהּ וְהֶפְדָּהּ לְעַם נָכְרִי לֹא־יִמְשֹׁל לְמָכְרָהּ בְּבִגְדוֹ־בָהּ׃
וְאִם־לִבְנוֹ יִיעָדֶנָּה כְּמִשְׁפַּט הַבָּנוֹת יַעֲשֶׂה־לָּהּ׃
אִם־אַחֶרֶת יִקַּח־לוֹ שְׁאֵרָהּ כְּסוּתָהּ וְעֹנָתָהּ לֹא יִגְרָע׃
וְאִם־שְׁלָשׁ־אֵלֶּה לֹא יַעֲשֶׂה לָהּ וְיָצְאָה חִנָּם אֵין כָּסֶף׃
מַכֵּה אִישׁ וָמֵת מוֹת יוּמָת׃
וַאֲשֶׁר לֹא צָדָה וְהָאֱלֹהִים אִנָּה לְיָדוֹ וְשַׂמְתִּי לְךָ מָקוֹם אֲשֶׁר יָנוּס שָׁמָּה׃
וְכִי־יָזִד אִישׁ עַל־רֵעֵהוּ לְהָרְגוֹ בְעָרְמָה מֵעִם מִזְבְּחִי תִּקָּחֶנּוּ לָמוּת׃
וּמַכֵּה אָבִיו וְאִמּוֹ מוֹת יוּמָת׃
וְגֹנֵב אִישׁ וּמְכָרוֹ וְנִמְצָא בְיָדוֹ מוֹת יוּמָת׃
וּמְקַלֵּל אָבִיו וְאִמּוֹ מוֹת יוּמָת׃
וְכִי־יְרִיבֻן אֲנָשִׁים וְהִכָּה־אִישׁ אֶת־רֵעֵהוּ בְּאֶבֶן אוֹ בְאֶגְרֹף וְלֹא יָמוּת וְנָפַל לְמִשְׁכָּב׃
אִם־יָקוּם וְהִתְהַלֵּךְ בַּחוּץ עַל־מִשְׁעַנְתּוֹ וְנִקָּה הַמַּכֶּה רַק שִׁבְתּוֹ יִתֵּן וְרַפֹּא יְרַפֵּא׃
וְכִי־יַכֶּה אִישׁ אֶת־עַבְדּוֹ אוֹ אֶת־אֲמָתוֹ בַּשֵּׁבֶט וּמֵת תַּחַת יָדוֹ נָקֹם יִנָּקֵם׃
אַךְ אִם־יוֹם אוֹ יוֹמַיִם יַעֲמֹד לֹא יֻקַּם כִּי כַסְפּוֹ הוּא׃
וְכִי־יִנָּצוּ אֲנָשִׁים וְנָגְפוּ אִשָּׁה הָרָה וְיָצְאוּ יְלָדֶיהָ וְלֹא יִהְיֶה אָסוֹן עָנוֹשׁ יֵעָנֵשׁ כַּאֲשֶׁר יָשִׁית עָלָיו בַּעַל הָאִשָּׁה וְנָתַן בִּפְלִלִים׃
וְאִם־אָסוֹן יִהְיֶה וְנָתַתָּה נֶפֶשׁ תַּחַת נָפֶשׁ׃
עַיִן תַּחַת עַיִן שֵׁן תַּחַת שֵׁן יָד תַּחַת יָד רֶגֶל תַּחַת רָגֶל׃
כְּוִיָּה תַּחַת כְּוִיָּה פֶּצַע תַּחַת פָּצַע חַבּוּרָה תַּחַת חַבּוּרָה׃
וְכִי־יַכֶּה אִישׁ אֶת־עֵין עַבְדּוֹ אוֹ־אֶת־עֵין אֲמָתוֹ וְשִׁחֲתָהּ לַחָפְשִׁי יְשַׁלְּחֶנּוּ תַּחַת עֵינוֹ׃
וְאִם־שֵׁן עַבְדּוֹ אוֹ־שֵׁן אֲמָתוֹ יַפִּיל לַחָפְשִׁי יְשַׁלְּחֶנּוּ תַּחַת שִׁנּוֹ׃
וְכִי־יִגַּח שׁוֹר אֶת־אִישׁ אוֹ אֶת־אִשָּׁה וָמֵת סָקוֹל יִסָּקֵל הַשּׁוֹר וְלֹא יֵאָכֵל אֶת־בְּשָׂרוֹ וּבַעַל הַשּׁוֹר נָקִי׃
וְאִם שׁוֹר נַגָּח הוּא מִתְּמֹל שִׁלְשֹׁם וְהוּעַד בִּבְעָלָיו וְלֹא יִשְׁמְרֶנּוּ וְהֵמִית אִישׁ אוֹ אִשָּׁה הַשּׁוֹר יִסָּקֵל וְגַם־בְּעָלָיו יוּמָת׃
אִם־כֹּפֶר יוּשַׁת עָלָיו וְנָתַן פִּדְיֹן נַפְשׁוֹ כְּכֹל אֲשֶׁר־יוּשַׁת עָלָיו׃
אוֹ־בֵן יִגָּח אוֹ־בַת יִגָּח כַּמִּשְׁפָּט הַזֶּה יֵעָשֶׂה לּוֹ׃
אִם־עֶבֶד יִגַּח הַשּׁוֹר אוֹ אָמָה כֶּסֶף שְׁלֹשִׁים שְׁקָלִים יִתֵּן לַאדֹנָיו וְהַשּׁוֹר יִסָּקֵל׃
וְכִי־יִפְתַּח אִישׁ בּוֹר אוֹ כִּי־יִכְרֶה אִישׁ בֹּר וְלֹא יְכַסֶּנּוּ וְנָפַל־שָׁמָּה שּׁוֹר אוֹ חֲמוֹר׃
בַּעַל הַבּוֹר יְשַׁלֵּם כֶּסֶף יָשִׁיב לִבְעָלָיו וְהַמֵּת יִהְיֶה־לּוֹ׃
וְכִי־יִגֹּף שׁוֹר־אִישׁ אֶת־שׁוֹר רֵעֵהוּ וָמֵת וּמָכְרוּ אֶת־הַשּׁוֹר הַחַי וְחָצוּ אֶת־כַּסְפּוֹ וְגַם אֶת־הַמֵּת יֶחֱצוּן׃
אוֹ נוֹדַע כִּי שׁוֹר נַגָּח הוּא מִתְּמוֹל שִׁלְשֹׁם וְלֹא יִשְׁמְרֶנּוּ בְּעָלָיו שַׁלֵּם יְשַׁלֵּם שׁוֹר תַּחַת הַשּׁוֹר וְהַמֵּת יִהְיֶה־לּוֹ׃
כִּי יִגְנֹב־אִישׁ שׁוֹר אוֹ־שֶׂה וּטְבָחוֹ אוֹ מְכָרוֹ חֲמִשָּׁה בָקָר יְשַׁלֵּם תַּחַת הַשּׁוֹר וְאַרְבַּע־צֹאן תַּחַת הַשֶּׂה׃

Chapter 22

אִם־בַּמַּחְתֶּרֶת יִמָּצֵא הַגַּנָּב וְהֻכָּה וָמֵת אֵין לוֹ דָּמִים׃
אִם־זָרְחָה הַשֶּׁמֶשׁ עָלָיו דָּמִים לוֹ שַׁלֵּם יְשַׁלֵּם אִם־אֵין לוֹ וְנִמְכַּר בִּגְנֵבָתוֹ׃
אִם־הִמָּצֵא תִמָּצֵא בְיָדוֹ הַגְּנֵבָה מִשּׁוֹר עַד־חֲמוֹר עַד־שֶׂה חַיִּים שְׁנַיִם יְשַׁלֵּם׃
כִּי יַבְעֶר־אִישׁ שָׂדֶה אוֹ־כֶרֶם וְשִׁלַּח אֶת־בעירה [בְּעִירוֹ] וּבִעֵר בִּשְׂדֵה אַחֵר מֵיטַב שָׂדֵהוּ וּמֵיטַב כַּרְמוֹ יְשַׁלֵּם׃
כִּי־תֵצֵא אֵשׁ וּמָצְאָה קֹצִים וְנֶאֱכַל גָּדִישׁ אוֹ הַקָּמָה אוֹ הַשָּׂדֶה שַׁלֵּם יְשַׁלֵּם הַמַּבְעִר אֶת־הַבְּעֵרָה׃
כִּי־יִתֵּן אִישׁ אֶל־רֵעֵהוּ כֶּסֶף אוֹ־כֵלִים לִשְׁמֹר וְגֻנַּב מִבֵּית הָאִישׁ אִם־יִמָּצֵא הַגַּנָּב יְשַׁלֵּם שְׁנָיִם׃
אִם־לֹא יִמָּצֵא הַגַּנָּב וְנִקְרַב בַּעַל־הַבַּיִת אֶל־הָאֱלֹהִים אִם־לֹא שָׁלַח יָדוֹ בִּמְלֶאכֶת רֵעֵהוּ׃
עַל־כָּל־דְּבַר־פֶּשַׁע עַל־שׁוֹר עַל־חֲמוֹר עַל־שֶׂה עַל־שַׂלְמָה עַל־כָּל־אֲבֵדָה אֲשֶׁר יֹאמַר כִּי־הוּא זֶה עַד הָאֱלֹהִים יָבֹא דְּבַר־שְׁנֵיהֶם אֲשֶׁר יַרְשִׁיעֻן אֱלֹהִים יְשַׁלֵּם שְׁנַיִם לְרֵעֵהוּ׃
כִּי־יִתֵּן אִישׁ אֶל־רֵעֵהוּ חֲמוֹר אוֹ־שׁוֹר אוֹ־שֶׂה וְכָל־בְּהֵמָה לִשְׁמֹר וּמֵת אוֹ־נִשְׁבַּר אוֹ־נִשְׁבָּה אֵין רֹאֶה׃
שְׁבֻעַת יְהוָה תִּהְיֶה בֵּין שְׁנֵיהֶם אִם־לֹא שָׁלַח יָדוֹ בִּמְלֶאכֶת רֵעֵהוּ וְלָקַח בְּעָלָיו וְלֹא יְשַׁלֵּם׃
וְאִם־גָּנֹב יִגָּנֵב מֵעִמּוֹ יְשַׁלֵּם לִבְעָלָיו׃
אִם־טָרֹף יִטָּרֵף יְבִאֵהוּ עֵד הַטְּרֵפָה לֹא יְשַׁלֵּם׃
וְכִי־יִשְׁאַל אִישׁ מֵעִם רֵעֵהוּ וְנִשְׁבַּר אוֹ־מֵת בְּעָלָיו אֵין־עִמּוֹ שַׁלֵּם יְשַׁלֵּם׃
אִם־בְּעָלָיו עִמּוֹ לֹא יְשַׁלֵּם אִם־שָׂכִיר הוּא בָּא בִּשְׂכָרוֹ׃
וְכִי־יְפַתֶּה אִישׁ בְּתוּלָה אֲשֶׁר לֹא־אֹרָשָׂה וְשָׁכַב עִמָּהּ מָהֹר יִמְהָרֶנָּה לּוֹ לְאִשָּׁה׃
אִם־מָאֵן יְמָאֵן אָבִיהָ לְתִתָּהּ לוֹ כֶּסֶף יִשְׁקֹל כְּמֹהַר הַבְּתוּלֹת׃
מְכַשֵּׁפָה לֹא תְחַיֶּה׃
כָּל־שֹׁכֵב עִם־בְּהֵמָה מוֹת יוּמָת׃
זֹבֵחַ לָאֱלֹהִים יָחֳרָם בִּלְתִּי לַיהוָה לְבַדּוֹ׃
וְגֵר לֹא־תוֹנֶה וְלֹא תִלְחָצֶנּוּ כִּי־גֵרִים הֱיִיתֶם בְּאֶרֶץ מִצְרָיִם׃
כָּל־אַלְמָנָה וְיָתוֹם לֹא תְעַנּוּן׃
אִם־עַנֵּה תְעַנֶּה אֹתוֹ כִּי אִם־צָעֹק יִצְעַק אֵלַי שָׁמֹעַ אֶשְׁמַע צַעֲקָתוֹ׃
וְחָרָה אַפִּי וְהָרַגְתִּי אֶתְכֶם בֶּחָרֶב וְהָיוּ נְשֵׁיכֶם אַלְמָנוֹת וּבְנֵיכֶם יְתֹמִים׃
אִם־כֶּסֶף תַּלְוֶה אֶת־עַמִּי אֶת־הֶעָנִי עִמָּךְ לֹא־תִהְיֶה לוֹ כְּנֹשֶׁה לֹא־תְשִׂימוּן עָלָיו נֶשֶׁךְ׃
אִם־חָבֹל תַּחְבֹּל שַׂלְמַת רֵעֶךָ עַד־בֹּא הַשֶּׁמֶשׁ תְּשִׁיבֶנּוּ לוֹ׃
כִּי הִוא כסותה [כְסוּתוֹ] לְבַדָּהּ הִוא שִׂמְלָתוֹ לְעֹרוֹ בַּמֶּה יִשְׁכָּב וְהָיָה כִּי־יִצְעַק אֵלַי וְשָׁמַעְתִּי כִּי־חַנּוּן אָנִי׃
אֱלֹהִים לֹא תְקַלֵּל וְנָשִׂיא בְעַמְּךָ לֹא תָאֹר׃
מְלֵאָתְךָ וְדִמְעֲךָ לֹא תְאַחֵר בְּכוֹר בָּנֶיךָ תִּתֶּן־לִּי׃
כֵּן־תַּעֲשֶׂה לְשֹׁרְךָ לְצֹאנֶךָ שִׁבְעַת יָמִים יִהְיֶה עִם־אִמּוֹ בַּיּוֹם הַשְּׁמִינִי תִּתְּנוֹ־לִי׃
וְאַנְשֵׁי־קֹדֶשׁ תִּהְיוּן לִי וּבָשָׂר בַּשָּׂדֶה טְרֵפָה לֹא תֹאכֵלוּ לַכֶּלֶב תַּשְׁלִכוּן אֹתוֹ׃

Chapter 23

לֹא תִשָּׂא שֵׁמַע שָׁוְא אַל־תָּשֶׁת יָדְךָ עִם־רָשָׁע לִהְיֹת עֵד חָמָס׃
לֹא־תִהְיֶה אַחֲרֵי־רַבִּים לְרָעֹת וְלֹא־תַעֲנֶה עַל־רִב לִנְטֹת אַחֲרֵי רַבִּים לְהַטֹּת׃
וְדָל לֹא תֶהְדַּר בְּרִיבוֹ׃
כִּי תִפְגַּע שׁוֹר אֹיִבְךָ אוֹ חֲמֹרוֹ תֹּעֶה הָשֵׁב תְּשִׁיבֶנּוּ לוֹ׃
כִּי־תִרְאֶה חֲמוֹר שֹׂנַאֲךָ רֹבֵץ תַּחַת מַשָּׂאוֹ וְחָדַלְתָּ מֵעֲזֹב לוֹ עָזֹב תַּעֲזֹב עִמּוֹ׃
לֹא תַטֶּה מִשְׁפַּט אֶבְיֹנְךָ בְּרִיבוֹ׃
מִדְּבַר־שֶׁקֶר תִּרְחָק וְנָקִי וְצַדִּיק אַל־תַּהֲרֹג כִּי לֹא־אַצְדִּיק רָשָׁע׃
וְשֹׁחַד לֹא תִקָּח כִּי הַשֹּׁחַד יְעַוֵּר פִּקְחִים וִיסַלֵּף דִּבְרֵי צַדִּיקִים׃
וְגֵר לֹא תִלְחָץ וְאַתֶּם יְדַעְתֶּם אֶת־נֶפֶשׁ הַגֵּר כִּי־גֵרִים הֱיִיתֶם בְּאֶרֶץ מִצְרָיִם׃
וְשֵׁשׁ שָׁנִים תִּזְרַע אֶת־אַרְצֶךָ וְאָסַפְתָּ אֶת־תְּבוּאָתָהּ׃
וְהַשְּׁבִיעִת תִּשְׁמְטֶנָּה וּנְטַשְׁתָּהּ וְאָכְלוּ אֶבְיֹנֵי עַמֶּךָ וְיִתְרָם תֹּאכַל חַיַּת הַשָּׂדֶה כֵּן־תַּעֲשֶׂה לְכַרְמְךָ לְזֵיתֶךָ׃
שֵׁשֶׁת יָמִים תַּעֲשֶׂה מַעֲשֶׂיךָ וּבַיּוֹם הַשְּׁבִיעִי תִּשְׁבֹּת לְמַעַן יָנוּחַ שׁוֹרְךָ וַחֲמֹרֶךָ וְיִנָּפֵשׁ בֶּן־אֲמָתְךָ וְהַגֵּר׃
וּבְכֹל אֲשֶׁר־אָמַרְתִּי אֲלֵיכֶם תִּשָּׁמֵרוּ וְשֵׁם אֱלֹהִים אֲחֵרִים לֹא תַזְכִּירוּ לֹא יִשָּׁמַע עַל־פִּיךָ׃
שָׁלֹשׁ רְגָלִים תָּחֹג לִי בַּשָּׁנָה׃
אֶת־חַג הַמַּצּוֹת תִּשְׁמֹר שִׁבְעַת יָמִים תֹּאכַל מַצּוֹת כַּאֲשֶׁר צִוִּיתִךָ לְמוֹעֵד חֹדֶשׁ הָאָבִיב כִּי־בוֹ יָצָאתָ מִמִּצְרָיִם וְלֹא־יֵרָאוּ פָנַי רֵיקָם׃
וְחַג הַקָּצִיר בִּכּוּרֵי מַעֲשֶׂיךָ אֲשֶׁר תִּזְרַע בַּשָּׂדֶה וְחַג הָאָסִף בְּצֵאת הַשָּׁנָה בְּאָסְפְּךָ אֶת־מַעֲשֶׂיךָ מִן־הַשָּׂדֶה׃
שָׁלֹשׁ פְּעָמִים בַּשָּׁנָה יֵרָאֶה כָּל־זְכוּרְךָ אֶל־פְּנֵי הָאָדֹן יְהוָה׃
לֹא־תִזְבַּח עַל־חָמֵץ דַּם־זִבְחִי וְלֹא־יָלִין חֵלֶב־חַגִּי עַד־בֹּקֶר׃
רֵאשִׁית בִּכּוּרֵי אַדְמָתְךָ תָּבִיא בֵּית יְהוָה אֱלֹהֶיךָ לֹא־תְבַשֵּׁל גְּדִי בַּחֲלֵב אִמּוֹ׃
הִנֵּה אָנֹכִי שֹׁלֵחַ מַלְאָךְ לְפָנֶיךָ לִשְׁמָרְךָ בַּדָּרֶךְ וְלַהֲבִיאֲךָ אֶל־הַמָּקוֹם אֲשֶׁר הֲכִנֹתִי׃
הִשָּׁמֶר מִפָּנָיו וּשְׁמַע בְּקֹלוֹ אַל־תַּמֵּר בּוֹ כִּי לֹא יִשָּׂא לְפִשְׁעֲכֶם כִּי שְׁמִי בְּקִרְבּוֹ׃
כִּי אִם־שָׁמֹעַ תִּשְׁמַע בְּקֹלוֹ וְעָשִׂיתָ כֹּל אֲשֶׁר אֲדַבֵּר וְאָיַבְתִּי אֶת־אֹיְבֶיךָ וְצַרְתִּי אֶת־צֹרְרֶיךָ׃
כִּי־יֵלֵךְ מַלְאָכִי לְפָנֶיךָ וֶהֱבִיאֲךָ אֶל־הָאֱמֹרִי וְהַחִתִּי וְהַפְּרִזִּי וְהַכְּנַעֲנִי הַחִוִּי וְהַיְבוּסִי וְהִכְחַדְתִּיו׃
לֹא־תִשְׁתַּחֲוֶה לֵאלֹהֵיהֶם וְלֹא תָעָבְדֵם וְלֹא תַעֲשֶׂה כְּמַעֲשֵׂיהֶם כִּי הָרֵס תְּהָרְסֵם וְשַׁבֵּר תְּשַׁבֵּר מַצֵּבֹתֵיהֶם׃
וַעֲבַדְתֶּם אֵת יְהוָה אֱלֹהֵיכֶם וּבֵרַךְ אֶת־לַחְמְךָ וְאֶת־מֵימֶיךָ וַהֲסִרֹתִי מַחֲלָה מִקִּרְבֶּךָ׃
לֹא תִהְיֶה מְשַׁכֵּלָה וַעֲקָרָה בְּאַרְצֶךָ אֶת־מִסְפַּר יָמֶיךָ אֲמַלֵּא׃
אֶת־אֵימָתִי אֲשַׁלַּח לְפָנֶיךָ וְהַמֹּתִי אֶת־כָּל־הָעָם אֲשֶׁר תָּבֹא בָּהֶם וְנָתַתִּי אֶת־כָּל־אֹיְבֶיךָ אֵלֶיךָ עֹרֶף׃
וְשָׁלַחְתִּי אֶת־הַצִּרְעָה לְפָנֶיךָ וְגֵרְשָׁה אֶת־הַחִוִּי אֶת־הַכְּנַעֲנִי וְאֶת־הַחִתִּי מִלְּפָנֶיךָ׃
לֹא אֲגָרְשֶׁנּוּ מִפָּנֶיךָ בְּשָׁנָה אֶחָת פֶּן־תִּהְיֶה הָאָרֶץ שְׁמָמָה וְרַבָּה עָלֶיךָ חַיַּת הַשָּׂדֶה׃
מְעַט מְעַט אֲגָרְשֶׁנּוּ מִפָּנֶיךָ עַד אֲשֶׁר תִּפְרֶה וְנָחַלְתָּ אֶת־הָאָרֶץ׃
וְשַׁתִּי אֶת־גְּבֻלְךָ מִיַּם־סוּף וְעַד־יָם פְּלִשְׁתִּים וּמִמִּדְבָּר עַד־הַנָּהָר כִּי אֶתֵּן בְּיֶדְכֶם אֵת יֹשְׁבֵי הָאָרֶץ וְגֵרַשְׁתָּמוֹ מִפָּנֶיךָ׃
לֹא־תִכְרֹת לָהֶם וְלֵאלֹהֵיהֶם בְּרִית׃
לֹא יֵשְׁבוּ בְּאַרְצְךָ פֶּן־יַחֲטִיאוּ אֹתְךָ לִי כִּי תַעֲבֹד אֶת־אֱלֹהֵיהֶם כִּי־יִהְיֶה לְךָ לְמוֹקֵשׁ׃

Chapter 24

וְאֶל־מֹשֶׁה אָמַר עֲלֵה אֶל־יְהוָה אַתָּה וְאַהֲרֹן נָדָב וַאֲבִיהוּא וְשִׁבְעִים מִזִּקְנֵי יִשְׂרָאֵל וְהִשְׁתַּחֲוִיתֶם מֵרָחֹק׃
וְנִגַּשׁ מֹשֶׁה לְבַדּוֹ אֶל־יְהוָה וְהֵם לֹא יִגָּשׁוּ וְהָעָם לֹא יַעֲלוּ עִמּוֹ׃
וַיָּבֹא מֹשֶׁה וַיְסַפֵּר לָעָם אֵת כָּל־דִּבְרֵי יְהוָה וְאֵת כָּל־הַמִּשְׁפָּטִים וַיַּעַן כָּל־הָעָם קוֹל אֶחָד וַיֹּאמְרוּ כָּל־הַדְּבָרִים אֲשֶׁר־דִּבֶּר יְהוָה נַעֲשֶׂה׃
וַיִּכְתֹּב מֹשֶׁה אֵת כָּל־דִּבְרֵי יְהוָה וַיַּשְׁכֵּם בַּבֹּקֶר וַיִּבֶן מִזְבֵּחַ תַּחַת הָהָר וּשְׁתֵּים עֶשְׂרֵה מַצֵּבָה לִשְׁנֵים עָשָׂר שִׁבְטֵי יִשְׂרָאֵל׃
וַיִּשְׁלַח אֶת־נַעֲרֵי בְּנֵי יִשְׂרָאֵל וַיַּעֲלוּ עֹלֹת וַיִּזְבְּחוּ זְבָחִים שְׁלָמִים לַיהוָה פָּרִים׃
וַיִּקַּח מֹשֶׁה חֲצִי הַדָּם וַיָּשֶׂם בָּאַגָּנֹת וַחֲצִי הַדָּם זָרַק עַל־הַמִּזְבֵּחַ׃
וַיִּקַּח סֵפֶר הַבְּרִית וַיִּקְרָא בְּאָזְנֵי הָעָם וַיֹּאמְרוּ כֹּל אֲשֶׁר־דִּבֶּר יְהוָה נַעֲשֶׂה וְנִשְׁמָע׃
וַיִּקַּח מֹשֶׁה אֶת־הַדָּם וַיִּזְרֹק עַל־הָעָם וַיֹּאמֶר הִנֵּה דַם־הַבְּרִית אֲשֶׁר כָּרַת יְהוָה עִמָּכֶם עַל כָּל־הַדְּבָרִים הָאֵלֶּה׃
וַיַּעַל מֹשֶׁה וְאַהֲרֹן נָדָב וַאֲבִיהוּא וְשִׁבְעִים מִזִּקְנֵי יִשְׂרָאֵל׃
וַיִּרְאוּ אֵת אֱלֹהֵי יִשְׂרָאֵל וְתַחַת רַגְלָיו כְּמַעֲשֵׂה לִבְנַת הַסַּפִּיר וּכְעֶצֶם הַשָּׁמַיִם לָטֹהַר׃
וְאֶל־אֲצִילֵי בְּנֵי יִשְׂרָאֵל לֹא שָׁלַח יָדוֹ וַיֶּחֱזוּ אֶת־הָאֱלֹהִים וַיֹּאכְלוּ וַיִּשְׁתּוּ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עֲלֵה אֵלַי הָהָרָה וֶהְיֵה־שָׁם וְאֶתְּנָה לְךָ אֶת־לֻחֹת הָאֶבֶן וְהַתּוֹרָה וְהַמִּצְוָה אֲשֶׁר כָּתַבְתִּי לְהוֹרֹתָם׃
וַיָּקָם מֹשֶׁה וִיהוֹשֻׁעַ מְשָׁרְתוֹ וַיַּעַל מֹשֶׁה אֶל־הַר הָאֱלֹהִים׃
וְאֶל־הַזְּקֵנִים אָמַר שְׁבוּ־לָנוּ בָזֶה עַד אֲשֶׁר־נָשׁוּב אֲלֵיכֶם וְהִנֵּה אַהֲרֹן וְחוּר עִמָּכֶם מִי־בַעַל דְּבָרִים יִגַּשׁ אֲלֵהֶם׃
וַיַּעַל מֹשֶׁה אֶל־הָהָר וַיְכַס הֶעָנָן אֶת־הָהָר׃
וַיִּשְׁכֹּן כְּבוֹד־יְהוָה עַל־הַר סִינַי וַיְכַסֵּהוּ הֶעָנָן שֵׁשֶׁת יָמִים וַיִּקְרָא אֶל־מֹשֶׁה בַּיּוֹם הַשְּׁבִיעִי מִתּוֹךְ הֶעָנָן׃
וּמַרְאֵה כְּבוֹד יְהוָה כְּאֵשׁ אֹכֶלֶת בְּרֹאשׁ הָהָר לְעֵינֵי בְּנֵי יִשְׂרָאֵל׃
וַיָּבֹא מֹשֶׁה בְּתוֹךְ הֶעָנָן וַיַּעַל אֶל־הָהָר וַיְהִי מֹשֶׁה בָּהָר אַרְבָּעִים יוֹם וְאַרְבָּעִים לָיְלָה׃

Chapter 25

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְיִקְחוּ־לִי תְּרוּמָה מֵאֵת כָּל־אִישׁ אֲשֶׁר יִדְּבֶנּוּ לִבּוֹ תִּקְחוּ אֶת־תְּרוּמָתִי׃
וְזֹאת הַתְּרוּמָה אֲשֶׁר תִּקְחוּ מֵאִתָּם זָהָב וָכֶסֶף וּנְחֹשֶׁת׃
וּתְכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ וְעִזִּים׃
וְעֹרֹת אֵילִם מְאָדָּמִים וְעֹרֹת תְּחָשִׁים וַעֲצֵי שִׁטִּים׃
שֶׁמֶן לַמָּאֹר בְּשָׂמִים לְשֶׁמֶן הַמִּשְׁחָה וְלִקְטֹרֶת הַסַּמִּים׃
אַבְנֵי־שֹׁהַם וְאַבְנֵי מִלֻּאִים לָאֵפֹד וְלַחֹשֶׁן׃
וְעָשׂוּ לִי מִקְדָּשׁ וְשָׁכַנְתִּי בְּתוֹכָם׃
כְּכֹל אֲשֶׁר אֲנִי מַרְאֶה אוֹתְךָ אֵת תַּבְנִית הַמִּשְׁכָּן וְאֵת תַּבְנִית כָּל־כֵּלָיו וְכֵן תַּעֲשׂוּ׃
וְעָשׂוּ אֲרוֹן עֲצֵי שִׁטִּים אַמָּתַיִם וָחֵצִי אָרְכּוֹ וְאַמָּה וָחֵצִי רָחְבּוֹ וְאַמָּה וָחֵצִי קֹמָתוֹ׃
וְצִפִּיתָ אֹתוֹ זָהָב טָהוֹר מִבַּיִת וּמִחוּץ תְּצַפֶּנּוּ וְעָשִׂיתָ עָלָיו זֵר זָהָב סָבִיב׃
וְיָצַקְתָּ לּוֹ אַרְבַּע טַבְּעֹת זָהָב וְנָתַתָּה עַל אַרְבַּע פַּעֲמֹתָיו וּשְׁתֵּי טַבָּעֹת עַל־צַלְעוֹ הָאֶחָת וּשְׁתֵּי טַבָּעֹת עַל־צַלְעוֹ הַשֵּׁנִית׃
וְעָשִׂיתָ בַדֵּי עֲצֵי שִׁטִּים וְצִפִּיתָ אֹתָם זָהָב׃
וְהֵבֵאתָ אֶת־הַבַּדִּים בַּטַּבָּעֹת עַל צַלְעֹת הָאָרֹן לָשֵׂאת אֶת־הָאָרֹן בָּהֶם׃
בְּטַבְּעֹת הָאָרֹן יִהְיוּ הַבַּדִּים לֹא יָסֻרוּ מִמֶּנּוּ׃
וְנָתַתָּ אֶל־הָאָרֹן אֵת הָעֵדֻת אֲשֶׁר אֶתֵּן אֵלֶיךָ׃
וְעָשִׂיתָ כַפֹּרֶת זָהָב טָהוֹר אַמָּתַיִם וָחֵצִי אָרְכָּהּ וְאַמָּה וָחֵצִי רָחְבָּהּ׃
וְעָשִׂיתָ שְׁנַיִם כְּרֻבִים זָהָב מִקְשָׁה תַּעֲשֶׂה אֹתָם מִשְּׁנֵי קְצוֹת הַכַּפֹּרֶת׃
וַעֲשֵׂה כְּרוּב אֶחָד מִקָּצָה מִזֶּה וּכְרוּב־אֶחָד מִקָּצָה מִזֶּה מִן־הַכַּפֹּרֶת תַּעֲשׂוּ אֶת־הַכְּרֻבִים עַל־שְׁנֵי קְצוֹתָיו׃
וְהָיוּ הַכְּרֻבִים פֹּרְשֵׂי כְנָפַיִם לְמַעְלָה סֹכְכִים בְּכַנְפֵיהֶם עַל־הַכַּפֹּרֶת וּפְנֵיהֶם אִישׁ אֶל־אָחִיו אֶל־הַכַּפֹּרֶת יִהְיוּ פְּנֵי הַכְּרֻבִים׃
וְנָתַתָּ אֶת־הַכַּפֹּרֶת עַל־הָאָרֹן מִלְמָעְלָה וְאֶל־הָאָרֹן תִּתֵּן אֶת־הָעֵדֻת אֲשֶׁר אֶתֵּן אֵלֶיךָ׃
וְנוֹעַדְתִּי לְךָ שָׁם וְדִבַּרְתִּי אִתְּךָ מֵעַל הַכַּפֹּרֶת מִבֵּין שְׁנֵי הַכְּרֻבִים אֲשֶׁר עַל־אֲרֹן הָעֵדֻת אֵת כָּל־אֲשֶׁר אֲצַוֶּה אוֹתְךָ אֶל־בְּנֵי יִשְׂרָאֵל׃
וְעָשִׂיתָ שֻׁלְחָן עֲצֵי שִׁטִּים אַמָּתַיִם אָרְכּוֹ וְאַמָּה רָחְבּוֹ וְאַמָּה וָחֵצִי קֹמָתוֹ׃
וְצִפִּיתָ אֹתוֹ זָהָב טָהוֹר וְעָשִׂיתָ לּוֹ זֵר זָהָב סָבִיב׃
וְעָשִׂיתָ לּוֹ מִסְגֶּרֶת טֹפַח סָבִיב וְעָשִׂיתָ זֵר־זָהָב לְמִסְגַּרְתּוֹ סָבִיב׃
וְעָשִׂיתָ לּוֹ אַרְבַּע טַבְּעֹת זָהָב וְנָתַתָּ אֶת־הַטַּבָּעֹת עַל אַרְבַּע הַפֵּאֹת אֲשֶׁר לְאַרְבַּע רַגְלָיו׃
לְעֻמַּת הַמִּסְגֶּרֶת תִּהְיֶיןָ הַטַּבָּעֹת לְבָתִּים לְבַדִּים לָשֵׂאת אֶת־הַשֻּׁלְחָן׃
וְעָשִׂיתָ אֶת־הַבַּדִּים עֲצֵי שִׁטִּים וְצִפִּיתָ אֹתָם זָהָב וְנִשָּׂא־בָם אֶת־הַשֻּׁלְחָן׃
וְעָשִׂיתָ קְּעָרֹתָיו וְכַפֹּתָיו וּקְשׂוֹתָיו וּמְנַקִּיֹּתָיו אֲשֶׁר יֻסַּךְ בָּהֵן זָהָב טָהוֹר תַּעֲשֶׂה אֹתָם׃
וְנָתַתָּ עַל־הַשֻּׁלְחָן לֶחֶם פָּנִים לְפָנַי תָּמִיד׃
וְעָשִׂיתָ מְנֹרַת זָהָב טָהוֹר מִקְשָׁה תֵּעָשֶׂה הַמְּנוֹרָה יְרֵכָהּ וְקָנָהּ גְּבִיעֶיהָ כַּפְתֹּרֶיהָ וּפְרָחֶיהָ מִמֶּנָּה יִהְיוּ׃
וְשִׁשָּׁה קָנִים יֹצְאִים מִצִּדֶּיהָ שְׁלֹשָׁה קְנֵי מְנֹרָה מִצִּדָּהּ הָאֶחָד וּשְׁלֹשָׁה קְנֵי מְנֹרָה מִצִּדָּהּ הַשֵּׁנִי׃
שְׁלֹשָׁה גְבִעִים מְשֻׁקָּדִים בַּקָּנֶה הָאֶחָד כַּפְתֹּר וָפֶרַח וּשְׁלֹשָׁה גְבִעִים מְשֻׁקָּדִים בַּקָּנֶה הָאֶחָד כַּפְתֹּר וָפָרַח כֵּן לְשֵׁשֶׁת הַקָּנִים הַיֹּצְאִים מִן־הַמְּנֹרָה׃
וּבַמְּנֹרָה אַרְבָּעָה גְבִעִים מְשֻׁקָּדִים כַּפְתֹּרֶיהָ וּפְרָחֶיהָ׃
וְכַפְתֹּר תַּחַת שְׁנֵי הַקָּנִים מִמֶּנָּה וְכַפְתֹּר תַּחַת שְׁנֵי הַקָּנִים מִמֶּנָּה וְכַפְתֹּר תַּחַת־שְׁנֵי הַקָּנִים מִמֶּנָּה לְשֵׁשֶׁת הַקָּנִים הַיֹּצְאִים מִן־הַמְּנֹרָה׃
כַּפְתֹּרֵיהֶם וּקְנֹתָם מִמֶּנָּה יִהְיוּ כֻּלָּהּ מִקְשָׁה אַחַת זָהָב טָהוֹר׃
וְעָשִׂיתָ אֶת־נֵרֹתֶיהָ שִׁבְעָה וְהֶעֱלָה אֶת־נֵרֹתֶיהָ וְהֵאִיר עַל־עֵבֶר פָּנֶיהָ׃
וּמַלְקָחֶיהָ וּמַחְתֹּתֶיהָ זָהָב טָהוֹר׃
כִּכָּר זָהָב טָהוֹר יַעֲשֶׂה אֹתָהּ אֵת כָּל־הַכֵּלִים הָאֵלֶּה׃
וּרְאֵה וַעֲשֵׂה בְּתַבְנִיתָם אֲשֶׁר־אַתָּה מָרְאֶה בָּהָר׃

Chapter 26

וְאֶת־הַמִּשְׁכָּן תַּעֲשֶׂה עֶשֶׂר יְרִיעֹת שֵׁשׁ מָשְׁזָר וּתְכֵלֶת וְאַרְגָּמָן וְתֹלַעַת שָׁנִי כְּרֻבִים מַעֲשֵׂה חֹשֵׁב תַּעֲשֶׂה אֹתָם׃
אֹרֶךְ הַיְרִיעָה הָאַחַת שְׁמֹנֶה וְעֶשְׂרִים בָּאַמָּה וְרֹחַב אַרְבַּע בָּאַמָּה הַיְרִיעָה הָאֶחָת מִדָּה אַחַת לְכָל־הַיְרִיעֹת׃
חֲמֵשׁ הַיְרִיעֹת תִּהְיֶיןָ חֹבְרֹת אִשָּׁה אֶל־אֲחֹתָהּ וְחָמֵשׁ יְרִיעֹת חֹבְרֹת אִשָּׁה אֶל־אֲחֹתָהּ׃
וְעָשִׂיתָ לֻלְאֹת תְּכֵלֶת עַל שְׂפַת הַיְרִיעָה הָאֶחָת מִקָּצָה בַּחֹבָרֶת וְכֵן תַּעֲשֶׂה בִּשְׂפַת הַיְרִיעָה הַקִּיצוֹנָה בַּמַּחְבֶּרֶת הַשֵּׁנִית׃
חֲמִשִּׁים לֻלָאֹת תַּעֲשֶׂה בַּיְרִיעָה הָאֶחָת וַחֲמִשִּׁים לֻלָאֹת תַּעֲשֶׂה בִּקְצֵה הַיְרִיעָה אֲשֶׁר בַּמַּחְבֶּרֶת הַשֵּׁנִית מַקְבִּילֹת הַלֻּלָאֹת אִשָּׁה אֶל־אֲחֹתָהּ׃
וְעָשִׂיתָ חֲמִשִּׁים קַרְסֵי זָהָב וְחִבַּרְתָּ אֶת־הַיְרִיעֹת אִשָּׁה אֶל־אֲחֹתָהּ בַּקְּרָסִים וְהָיָה הַמִּשְׁכָּן אֶחָד׃
וְעָשִׂיתָ יְרִיעֹת עִזִּים לְאֹהֶל עַל־הַמִּשְׁכָּן עַשְׁתֵּי־עֶשְׂרֵה יְרִיעֹת תַּעֲשֶׂה אֹתָם׃
אֹרֶךְ הַיְרִיעָה הָאַחַת שְׁלֹשִׁים בָּאַמָּה וְרֹחַב אַרְבַּע בָּאַמָּה הַיְרִיעָה הָאֶחָת מִדָּה אַחַת לְעַשְׁתֵּי עֶשְׂרֵה יְרִיעֹת׃
וְחִבַּרְתָּ אֶת־חֲמֵשׁ הַיְרִיעֹת לְבָד וְאֶת־שֵׁשׁ הַיְרִיעֹת לְבָד וְכָפַלְתָּ אֶת־הַיְרִיעָה הַשִּׁשִּׁית אֶל־מוּל פְּנֵי הָאֹהֶל׃
וְעָשִׂיתָ חֲמִשִּׁים לֻלָאֹת עַל שְׂפַת הַיְרִיעָה הָאֶחָת הַקִּיצֹנָה בַּחֹבָרֶת וַחֲמִשִּׁים לֻלָאֹת עַל שְׂפַת הַיְרִיעָה הַחֹבֶרֶת הַשֵּׁנִית׃
וְעָשִׂיתָ קַרְסֵי נְחֹשֶׁת חֲמִשִּׁים וְהֵבֵאתָ אֶת־הַקְּרָסִים בַּלֻּלָאֹת וְחִבַּרְתָּ אֶת־הָאֹהֶל וְהָיָה אֶחָד׃
וְסֶרַח הָעֹדֵף בִּירִיעֹת הָאֹהֶל חֲצִי הַיְרִיעָה הָעֹדֶפֶת תִּסְרַח עַל אֲחֹרֵי הַמִּשְׁכָּן׃
וְהָאַמָּה מִזֶּה וְהָאַמָּה מִזֶּה בָּעֹדֵף בְּאֹרֶךְ יְרִיעֹת הָאֹהֶל יִהְיֶה סָרוּחַ עַל־צִדֵּי הַמִּשְׁכָּן מִזֶּה וּמִזֶּה לְכַסֹּתוֹ׃
וְעָשִׂיתָ מִכְסֶה לָאֹהֶל עֹרֹת אֵילִם מְאָדָּמִים וּמִכְסֵה עֹרֹת תְּחָשִׁים מִלְמָעְלָה׃
וְעָשִׂיתָ אֶת־הַקְּרָשִׁים לַמִּשְׁכָּן עֲצֵי שִׁטִּים עֹמְדִים׃
עֶשֶׂר אַמּוֹת אֹרֶךְ הַקָּרֶשׁ וְאַמָּה וַחֲצִי הָאַמָּה רֹחַב הַקֶּרֶשׁ הָאֶחָד׃
שְׁתֵּי יָדוֹת לַקֶּרֶשׁ הָאֶחָד מְשֻׁלָּבֹת אִשָּׁה אֶל־אֲחֹתָהּ כֵּן תַּעֲשֶׂה לְכֹל קַרְשֵׁי הַמִּשְׁכָּן׃
וְעָשִׂיתָ אֶת־הַקְּרָשִׁים לַמִּשְׁכָּן עֶשְׂרִים קֶרֶשׁ לִפְאַת נֶגְבָּה תֵימָנָה׃
וְאַרְבָּעִים אַדְנֵי־כֶסֶף תַּעֲשֶׂה תַּחַת עֶשְׂרִים הַקָּרֶשׁ שְׁנֵי אֲדָנִים תַּחַת־הַקֶּרֶשׁ הָאֶחָד לִשְׁתֵּי יְדֹתָיו וּשְׁנֵי אֲדָנִים תַּחַת־הַקֶּרֶשׁ הָאֶחָד לִשְׁתֵּי יְדֹתָיו׃
וּלְצֶלַע הַמִּשְׁכָּן הַשֵּׁנִית לִפְאַת צָפוֹן עֶשְׂרִים קָרֶשׁ׃
וְאַרְבָּעִים אַדְנֵיהֶם כָּסֶף שְׁנֵי אֲדָנִים תַּחַת הַקֶּרֶשׁ הָאֶחָד וּשְׁנֵי אֲדָנִים תַּחַת הַקֶּרֶשׁ הָאֶחָד׃
וּלְיַרְכְּתֵי הַמִּשְׁכָּן יָמָּה תַּעֲשֶׂה שִׁשָּׁה קְרָשִׁים׃
וּשְׁנֵי קְרָשִׁים תַּעֲשֶׂה לִמְקֻצְעֹת הַמִּשְׁכָּן בַּיַּרְכָתָיִם׃
וְיִהְיוּ תֹאֲמִים מִלְּמַטָּה וְיַחְדָּו יִהְיוּ תַמִּים עַל־רֹאשׁוֹ אֶל־הַטַּבַּעַת הָאֶחָת כֵּן יִהְיֶה לִשְׁנֵיהֶם לִשְׁנֵי הַמִּקְצֹעֹת יִהְיוּ׃
וְהָיוּ שְׁמֹנָה קְרָשִׁים וְאַדְנֵיהֶם כֶּסֶף שִׁשָּׁה עָשָׂר אֲדָנִים שְׁנֵי אֲדָנִים תַּחַת הַקֶּרֶשׁ הָאֶחָד וּשְׁנֵי אֲדָנִים תַּחַת הַקֶּרֶשׁ הָאֶחָד׃
וְעָשִׂיתָ בְרִיחִם עֲצֵי שִׁטִּים חֲמִשָּׁה לְקַרְשֵׁי צֶלַע־הַמִּשְׁכָּן הָאֶחָד׃
וַחֲמִשָּׁה בְרִיחִם לְקַרְשֵׁי צֶלַע־הַמִּשְׁכָּן הַשֵּׁנִית וַחֲמִשָּׁה בְרִיחִם לְקַרְשֵׁי צֶלַע הַמִּשְׁכָּן לַיַּרְכָתַיִם יָמָּה׃
וְהַבְּרִיחַ הַתִּיכֹן בְּתוֹךְ הַקְּרָשִׁים מַבְרִחַ מִן־הַקָּצֶה אֶל־הַקָּצֶה׃
וְאֶת־הַקְּרָשִׁים תְּצַפֶּה זָהָב וְאֶת־טַבְּעֹתֵיהֶם תַּעֲשֶׂה זָהָב בָּתִּים לַבְּרִיחִם וְצִפִּיתָ אֶת־הַבְּרִיחִם זָהָב׃
וַהֲקֵמֹתָ אֶת־הַמִּשְׁכָּן כְּמִשְׁפָּטוֹ אֲשֶׁר הָרְאֵיתָ בָּהָר׃
וְעָשִׂיתָ פָרֹכֶת תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר מַעֲשֵׂה חֹשֵׁב יַעֲשֶׂה אֹתָהּ כְּרֻבִים׃
וְנָתַתָּה אֹתָהּ עַל־אַרְבָּעָה עַמּוּדֵי שִׁטִּים מְצֻפִּים זָהָב וָוֵיהֶם זָהָב עַל־אַרְבָּעָה אַדְנֵי־כָסֶף׃
וְנָתַתָּה אֶת־הַפָּרֹכֶת תַּחַת הַקְּרָסִים וְהֵבֵאתָ שָׁמָּה מִבֵּית לַפָּרֹכֶת אֵת אֲרוֹן הָעֵדוּת וְהִבְדִּילָה הַפָּרֹכֶת לָכֶם בֵּין הַקֹּדֶשׁ וּבֵין קֹדֶשׁ הַקֳּדָשִׁים׃
וְנָתַתָּ אֶת־הַכַּפֹּרֶת עַל אֲרוֹן הָעֵדֻת בְּקֹדֶשׁ הַקֳּדָשִׁים׃
וְשַׂמְתָּ אֶת־הַשֻּׁלְחָן מִחוּץ לַפָּרֹכֶת וְאֶת־הַמְּנֹרָה נֹכַח הַשֻּׁלְחָן עַל צֶלַע הַמִּשְׁכָּן תֵּימָנָה וְהַשֻּׁלְחָן תִּתֵּן עַל־צֶלַע צָפוֹן׃
וְעָשִׂיתָ מָסָךְ לְפֶתַח הָאֹהֶל תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר מַעֲשֵׂה רֹקֵם׃
וְעָשִׂיתָ לַמָּסָךְ חֲמִשָּׁה עַמּוּדֵי שִׁטִּים וְצִפִּיתָ אֹתָם זָהָב וָוֵיהֶם זָהָב וְיָצַקְתָּ לָהֶם חֲמִשָּׁה אַדְנֵי נְחֹשֶׁת׃

Chapter 27

וְעָשִׂיתָ אֶת־הַמִּזְבֵּחַ עֲצֵי שִׁטִּים חָמֵשׁ אַמּוֹת אֹרֶךְ וְחָמֵשׁ אַמּוֹת רֹחַב רָבוּעַ יִהְיֶה הַמִּזְבֵּחַ וְשָׁלֹשׁ אַמּוֹת קֹמָתוֹ׃
וְעָשִׂיתָ קַרְנֹתָיו עַל אַרְבַּע פִּנֹּתָיו מִמֶּנּוּ תִּהְיֶיןָ קַרְנֹתָיו וְצִפִּיתָ אֹתוֹ נְחֹשֶׁת׃
וְעָשִׂיתָ סִּירֹתָיו לְדַשְּׁנוֹ וְיָעָיו וּמִזְרְקֹתָיו וּמִזְלְגֹתָיו וּמַחְתֹּתָיו לְכָל־כֵּלָיו תַּעֲשֶׂה נְחֹשֶׁת׃
וְעָשִׂיתָ לּוֹ מִכְבָּר מַעֲשֵׂה רֶשֶׁת נְחֹשֶׁת וְעָשִׂיתָ עַל־הָרֶשֶׁת אַרְבַּע טַבְּעֹת נְחֹשֶׁת עַל אַרְבַּע קְצוֹתָיו׃
וְנָתַתָּה אֹתָהּ תַּחַת כַּרְכֹּב הַמִּזְבֵּחַ מִלְּמָטָּה וְהָיְתָה הָרֶשֶׁת עַד חֲצִי הַמִּזְבֵּחַ׃
וְעָשִׂיתָ בַדִּים לַמִּזְבֵּחַ בַּדֵּי עֲצֵי שִׁטִּים וְצִפִּיתָ אֹתָם נְחֹשֶׁת׃
וְהוּבָא אֶת־בַּדָּיו בַּטַּבָּעֹת וְהָיוּ הַבַּדִּים עַל־שְׁתֵּי צַלְעֹת הַמִּזְבֵּחַ בִּשְׂאֵת אֹתוֹ׃
נְבוּב לֻחֹת תַּעֲשֶׂה אֹתוֹ כַּאֲשֶׁר הֶרְאָה אֹתְךָ בָּהָר כֵּן יַעֲשׂוּ׃
וְעָשִׂיתָ אֵת חֲצַר הַמִּשְׁכָּן לִפְאַת נֶגֶב־תֵּימָנָה קְלָעִים לֶחָצֵר שֵׁשׁ מָשְׁזָר מֵאָה בָאַמָּה אֹרֶךְ לַפֵּאָה הָאֶחָת׃
וְעַמֻּדָיו עֶשְׂרִים וְאַדְנֵיהֶם עֶשְׂרִים נְחֹשֶׁת וָוֵי הָעַמֻּדִים וַחֲשֻׁקֵיהֶם כָּסֶף׃
וְכֵן לִפְאַת צָפוֹן בָּאֹרֶךְ קְלָעִים מֵאָה אֹרֶךְ ועמדו [וְעַמּוּדָיו] עֶשְׂרִים וְאַדְנֵיהֶם עֶשְׂרִים נְחֹשֶׁת וָוֵי הָעַמֻּדִים וַחֲשֻׁקֵיהֶם כָּסֶף׃
וְרֹחַב הֶחָצֵר לִפְאַת־יָם קְלָעִים חֲמִשִּׁים אַמָּה עַמֻּדֵיהֶם עֲשָׂרָה וְאַדְנֵיהֶם עֲשָׂרָה׃
וְרֹחַב הֶחָצֵר לִפְאַת קֵדְמָה מִזְרָחָה חֲמִשִּׁים אַמָּה׃
וַחֲמֵשׁ עֶשְׂרֵה אַמָּה קְלָעִים לַכָּתֵף עַמֻּדֵיהֶם שְׁלֹשָׁה וְאַדְנֵיהֶם שְׁלֹשָׁה׃
וְלַכָּתֵף הַשֵּׁנִית חְמֵשׁ עֶשְׂרֵה קְלָעִים עַמֻּדֵיהֶם שְׁלֹשָׁה וְאַדְנֵיהֶם שְׁלֹשָׁה׃
וּלְשַׁעַר הֶחָצֵר מָסָךְ עֶשְׂרִים אַמָּה תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר מַעֲשֵׂה רֹקֵם עַמֻּדֵיהֶם אַרְבָּעָה וְאַדְנֵיהֶם אַרְבָּעָה׃
כָּל־עַמּוּדֵי הֶחָצֵר סָבִיב מְחֻשָּׁקִים כֶּסֶף וָוֵיהֶם כָּסֶף וְאַדְנֵיהֶם נְחֹשֶׁת׃
אֹרֶךְ הֶחָצֵר מֵאָה בָאַמָּה וְרֹחַב חֲמִשִּׁים בַּחֲמִשִּׁים וְקֹמָה חָמֵשׁ אַמּוֹת שֵׁשׁ מָשְׁזָר וְאַדְנֵיהֶם נְחֹשֶׁת׃
לְכֹל כְּלֵי הַמִּשְׁכָּן בְּכֹל עֲבֹדָתוֹ וְכָל־יְתֵדֹתָיו וְכָל־יִתְדֹת הֶחָצֵר נְחֹשֶׁת׃
וְאַתָּה תְּצַוֶּה אֶת־בְּנֵי יִשְׂרָאֵל וְיִקְחוּ אֵלֶיךָ שֶׁמֶן זַיִת זָךְ כָּתִית לַמָּאוֹר לְהַעֲלֹת נֵר תָּמִיד׃
בְּאֹהֶל מוֹעֵד מִחוּץ לַפָּרֹכֶת אֲשֶׁר עַל־הָעֵדֻת יַעֲרֹךְ אֹתוֹ אַהֲרֹן וּבָנָיו מֵעֶרֶב עַד־בֹּקֶר לִפְנֵי יְהוָה חֻקַּת עוֹלָם לְדֹרֹתָם מֵאֵת בְּנֵי יִשְׂרָאֵל׃

Chapter 28

וְאַתָּה הַקְרֵב אֵלֶיךָ אֶת־אַהֲרֹן אָחִיךָ וְאֶת־בָּנָיו אִתּוֹ מִתּוֹךְ בְּנֵי יִשְׂרָאֵל לְכַהֲנוֹ־לִי אַהֲרֹן נָדָב וַאֲבִיהוּא אֶלְעָזָר וְאִיתָמָר בְּנֵי אַהֲרֹן׃
וְעָשִׂיתָ בִגְדֵי־קֹדֶשׁ לְאַהֲרֹן אָחִיךָ לְכָבוֹד וּלְתִפְאָרֶת׃
וְאַתָּה תְּדַבֵּר אֶל־כָּל־חַכְמֵי־לֵב אֲשֶׁר מִלֵּאתִיו רוּחַ חָכְמָה וְעָשׂוּ אֶת־בִּגְדֵי אַהֲרֹן לְקַדְּשׁוֹ לְכַהֲנוֹ־לִי׃
וְאֵלֶּה הַבְּגָדִים אֲשֶׁר יַעֲשׂוּ חֹשֶׁן וְאֵפוֹד וּמְעִיל וּכְתֹנֶת תַּשְׁבֵּץ מִצְנֶפֶת וְאַבְנֵט וְעָשׂוּ בִגְדֵי־קֹדֶשׁ לְאַהֲרֹן אָחִיךָ וּלְבָנָיו לְכַהֲנוֹ־לִי׃
וְהֵם יִקְחוּ אֶת־הַזָּהָב וְאֶת־הַתְּכֵלֶת וְאֶת־הָאַרְגָּמָן וְאֶת־תּוֹלַעַת הַשָּׁנִי וְאֶת־הַשֵּׁשׁ׃
וְעָשׂוּ אֶת־הָאֵפֹד זָהָב תְּכֵלֶת וְאַרְגָּמָן תּוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר מַעֲשֵׂה חֹשֵׁב׃
שְׁתֵּי כְתֵפֹת חֹבְרֹת יִהְיֶה־לּוֹ אֶל־שְׁנֵי קְצוֹתָיו וְחֻבָּר׃
וְחֵשֶׁב אֲפֻדָּתוֹ אֲשֶׁר עָלָיו כְּמַעֲשֵׂהוּ מִמֶּנּוּ יִהְיֶה זָהָב תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר׃
וְלָקַחְתָּ אֶת־שְׁתֵּי אַבְנֵי־שֹׁהַם וּפִתַּחְתָּ עֲלֵיהֶם שְׁמוֹת בְּנֵי יִשְׂרָאֵל׃
שִׁשָּׁה מִשְּׁמֹתָם עַל הָאֶבֶן הָאֶחָת וְאֶת־שְׁמוֹת הַשִּׁשָּׁה הַנּוֹתָרִים עַל־הָאֶבֶן הַשֵּׁנִית כְּתוֹלְדֹתָם׃
מַעֲשֵׂה חָרַשׁ אֶבֶן פִּתּוּחֵי חֹתָם תְּפַתַּח אֶת־שְׁתֵּי הָאֲבָנִים עַל־שְׁמֹת בְּנֵי יִשְׂרָאֵל מֻסַבֹּת מִשְׁבְּצוֹת זָהָב תַּעֲשֶׂה אֹתָם׃
וְשַׂמְתָּ אֶת־שְׁתֵּי הָאֲבָנִים עַל כִּתְפֹת הָאֵפֹד אַבְנֵי זִכָּרֹן לִבְנֵי יִשְׂרָאֵל וְנָשָׂא אַהֲרֹן אֶת־שְׁמוֹתָם לִפְנֵי יְהוָה עַל־שְׁתֵּי כְתֵפָיו לְזִכָּרֹן׃
וְעָשִׂיתָ מִשְׁבְּצֹת זָהָב׃
וּשְׁתֵּי שַׁרְשְׁרֹת זָהָב טָהוֹר מִגְבָּלֹת תַּעֲשֶׂה אֹתָם מַעֲשֵׂה עֲבֹת וְנָתַתָּה אֶת־שַׁרְשְׁרֹת הָעֲבֹתֹת עַל־הַמִּשְׁבְּצֹת׃
וְעָשִׂיתָ חֹשֶׁן מִשְׁפָּט מַעֲשֵׂה חֹשֵׁב כְּמַעֲשֵׂה אֵפֹד תַּעֲשֶׂנּוּ זָהָב תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר תַּעֲשֶׂה אֹתוֹ׃
רָבוּעַ יִהְיֶה כָּפוּל זֶרֶת אָרְכּוֹ וְזֶרֶת רָחְבּוֹ׃
וּמִלֵּאתָ בוֹ מִלֻּאַת אֶבֶן אַרְבָּעָה טוּרִים אָבֶן טוּר אֹדֶם פִּטְדָה וּבָרֶקֶת הַטּוּר הָאֶחָד׃
וְהַטּוּר הַשֵּׁנִי נֹפֶךְ סַפִּיר וְיָהֲלֹם׃
וְהַטּוּר הַשְּׁלִישִׁי לֶשֶׁם שְׁבוֹ וְאַחְלָמָה׃
וְהַטּוּר הָרְבִיעִי תַּרְשִׁישׁ וְשֹׁהַם וְיָשְׁפֵה מְשֻׁבָּצִים זָהָב יִהְיוּ בְּמִלּוּאֹתָם׃
וְהָאֲבָנִים תִּהְיֶיןָ עַל־שְׁמֹת בְּנֵי־יִשְׂרָאֵל שְׁתֵּים עֶשְׂרֵה עַל־שְׁמֹתָם פִּתּוּחֵי חוֹתָם אִישׁ עַל־שְׁמוֹ תִּהְיֶיןָ לִשְׁנֵי עָשָׂר שָׁבֶט׃
וְעָשִׂיתָ עַל־הַחֹשֶׁן שַׁרְשֹׁת גַּבְלֻת מַעֲשֵׂה עֲבֹת זָהָב טָהוֹר׃
וְעָשִׂיתָ עַל־הַחֹשֶׁן שְׁתֵּי טַבְּעוֹת זָהָב וְנָתַתָּ אֶת־שְׁתֵּי הַטַּבָּעוֹת עַל־שְׁנֵי קְצוֹת הַחֹשֶׁן׃
וְנָתַתָּה אֶת־שְׁתֵּי עֲבֹתֹת הַזָּהָב עַל־שְׁתֵּי הַטַּבָּעֹת אֶל־קְצוֹת הַחֹשֶׁן׃
וְאֵת שְׁתֵּי קְצוֹת שְׁתֵּי הָעֲבֹתֹת תִּתֵּן עַל־שְׁתֵּי הַמִּשְׁבְּצוֹת וְנָתַתָּה עַל־כִּתְפוֹת הָאֵפֹד אֶל־מוּל פָּנָיו׃
וְעָשִׂיתָ שְׁתֵּי טַבְּעוֹת זָהָב וְשַׂמְתָּ אֹתָם עַל־שְׁנֵי קְצוֹת הַחֹשֶׁן עַל־שְׂפָתוֹ אֲשֶׁר אֶל־עֵבֶר הָאֵפֹד בָּיְתָה׃
וְעָשִׂיתָ שְׁתֵּי טַבְּעוֹת זָהָב וְנָתַתָּה אֹתָם עַל־שְׁתֵּי כִתְפוֹת הָאֵפוֹד מִלְּמַטָּה מִמּוּל פָּנָיו לְעֻמַּת מֶחְבַּרְתּוֹ מִמַּעַל לְחֵשֶׁב הָאֵפוֹד׃
וְיִרְכְּסוּ אֶת־הַחֹשֶׁן מטבעתו [מִטַּבְּעֹתָיו] אֶל־טַבְּעֹת הָאֵפֹד בִּפְתִיל תְּכֵלֶת לִהְיוֹת עַל־חֵשֶׁב הָאֵפוֹד וְלֹא־יִזַּח הַחֹשֶׁן מֵעַל הָאֵפוֹד׃
וְנָשָׂא אַהֲרֹן אֶת־שְׁמוֹת בְּנֵי־יִשְׂרָאֵל בְּחֹשֶׁן הַמִּשְׁפָּט עַל־לִבּוֹ בְּבֹאוֹ אֶל־הַקֹּדֶשׁ לְזִכָּרֹן לִפְנֵי־יְהוָה תָּמִיד׃
וְנָתַתָּ אֶל־חֹשֶׁן הַמִּשְׁפָּט אֶת־הָאוּרִים וְאֶת־הַתֻּמִּים וְהָיוּ עַל־לֵב אַהֲרֹן בְּבֹאוֹ לִפְנֵי יְהוָה וְנָשָׂא אַהֲרֹן אֶת־מִשְׁפַּט בְּנֵי־יִשְׂרָאֵל עַל־לִבּוֹ לִפְנֵי יְהוָה תָּמִיד׃
וְעָשִׂיתָ אֶת־מְעִיל הָאֵפוֹד כְּלִיל תְּכֵלֶת׃
וְהָיָה פִי־רֹאשׁוֹ בְּתוֹכוֹ שָׂפָה יִהְיֶה לְפִיו סָבִיב מַעֲשֵׂה אֹרֵג כְּפִי תַחְרָא יִהְיֶה־לּוֹ לֹא יִקָּרֵעַ׃
וְעָשִׂיתָ עַל־שׁוּלָיו רִמֹּנֵי תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי עַל־שׁוּלָיו סָבִיב וּפַעֲמֹנֵי זָהָב בְּתוֹכָם סָבִיב׃
פַּעֲמֹן זָהָב וְרִמּוֹן פַּעֲמֹן זָהָב וְרִמּוֹן עַל־שׁוּלֵי הַמְּעִיל סָבִיב׃
וְהָיָה עַל־אַהֲרֹן לְשָׁרֵת וְנִשְׁמַע קוֹלוֹ בְּבֹאוֹ אֶל־הַקֹּדֶשׁ לִפְנֵי יְהוָה וּבְצֵאתוֹ וְלֹא יָמוּת׃
וְעָשִׂיתָ צִּיץ זָהָב טָהוֹר וּפִתַּחְתָּ עָלָיו פִּתּוּחֵי חֹתָם קֹדֶשׁ לַיהוָה׃
וְשַׂמְתָּ אֹתוֹ עַל־פְּתִיל תְּכֵלֶת וְהָיָה עַל־הַמִּצְנָפֶת אֶל־מוּל פְּנֵי־הַמִּצְנֶפֶת יִהְיֶה׃
וְהָיָה עַל־מֵצַח אַהֲרֹן וְנָשָׂא אַהֲרֹן אֶת־עֲוֺן הַקֳּדָשִׁים אֲשֶׁר יַקְדִּישׁוּ בְּנֵי יִשְׂרָאֵל לְכָל־מַתְּנֹת קָדְשֵׁיהֶם וְהָיָה עַל־מִצְחוֹ תָּמִיד לְרָצוֹן לָהֶם לִפְנֵי יְהוָה׃
וְשִׁבַּצְתָּ הַכְּתֹנֶת שֵׁשׁ וְעָשִׂיתָ מִצְנֶפֶת שֵׁשׁ וְאַבְנֵט תַּעֲשֶׂה מַעֲשֵׂה רֹקֵם׃
וְלִבְנֵי אַהֲרֹן תַּעֲשֶׂה כֻתֳּנֹת וְעָשִׂיתָ לָהֶם אַבְנֵטִים וּמִגְבָּעוֹת תַּעֲשֶׂה לָהֶם לְכָבוֹד וּלְתִפְאָרֶת׃
וְהִלְבַּשְׁתָּ אֹתָם אֶת־אַהֲרֹן אָחִיךָ וְאֶת־בָּנָיו אִתּוֹ וּמָשַׁחְתָּ אֹתָם וּמִלֵּאתָ אֶת־יָדָם וְקִדַּשְׁתָּ אֹתָם וְכִהֲנוּ לִי׃
וַעֲשֵׂה לָהֶם מִכְנְסֵי־בָד לְכַסּוֹת בְּשַׂר עֶרְוָה מִמָּתְנַיִם וְעַד־יְרֵכַיִם יִהְיוּ׃
וְהָיוּ עַל־אַהֲרֹן וְעַל־בָּנָיו בְּבֹאָם אֶל־אֹהֶל מוֹעֵד אוֹ בְגִשְׁתָּם אֶל־הַמִּזְבֵּחַ לְשָׁרֵת בַּקֹּדֶשׁ וְלֹא־יִשְׂאוּ עָוֺן וָמֵתוּ חֻקַּת עוֹלָם לוֹ וּלְזַרְעוֹ אַחֲרָיו׃

Chapter 29

וְזֶה הַדָּבָר אֲשֶׁר־תַּעֲשֶׂה לָהֶם לְקַדֵּשׁ אֹתָם לְכַהֵן לִי לְקַח פַּר אֶחָד בֶּן־בָּקָר וְאֵילִם שְׁנַיִם תְּמִימִם׃
וְלֶחֶם מַצּוֹת וְחַלֹּת מַצֹּת בְּלוּלֹת בַּשֶּׁמֶן וּרְקִיקֵי מַצּוֹת מְשֻׁחִים בַּשָּׁמֶן סֹלֶת חִטִּים תַּעֲשֶׂה אֹתָם׃
וְנָתַתָּ אוֹתָם עַל־סַל אֶחָד וְהִקְרַבְתָּ אֹתָם בַּסָּל וְאֶת־הַפָּר וְאֵת שְׁנֵי הָאֵילִם׃
וְאֶת־אַהֲרֹן וְאֶת־בָּנָיו תַּקְרִיב אֶל־פֶּתַח אֹהֶל מוֹעֵד וְרָחַצְתָּ אֹתָם בַּמָּיִם׃
וְלָקַחְתָּ אֶת־הַבְּגָדִים וְהִלְבַּשְׁתָּ אֶת־אַהֲרֹן אֶת־הַכֻּתֹּנֶת וְאֵת מְעִיל הָאֵפֹד וְאֶת־הָאֵפֹד וְאֶת־הַחֹשֶׁן וְאָפַדְתָּ לוֹ בְּחֵשֶׁב הָאֵפֹד׃
וְשַׂמְתָּ הַמִּצְנֶפֶת עַל־רֹאשׁוֹ וְנָתַתָּ אֶת־נֵזֶר הַקֹּדֶשׁ עַל־הַמִּצְנָפֶת׃
וְלָקַחְתָּ אֶת־שֶׁמֶן הַמִּשְׁחָה וְיָצַקְתָּ עַל־רֹאשׁוֹ וּמָשַׁחְתָּ אֹתוֹ׃
וְאֶת־בָּנָיו תַּקְרִיב וְהִלְבַּשְׁתָּם כֻּתֳּנֹת׃
וְחָגַרְתָּ אֹתָם אַבְנֵט אַהֲרֹן וּבָנָיו וְחָבַשְׁתָּ לָהֶם מִגְבָּעֹת וְהָיְתָה לָהֶם כְּהֻנָּה לְחֻקַּת עוֹלָם וּמִלֵּאתָ יַד־אַהֲרֹן וְיַד־בָּנָיו׃
וְהִקְרַבְתָּ אֶת־הַפָּר לִפְנֵי אֹהֶל מוֹעֵד וְסָמַךְ אַהֲרֹן וּבָנָיו אֶת־יְדֵיהֶם עַל־רֹאשׁ הַפָּר׃
וְשָׁחַטְתָּ אֶת־הַפָּר לִפְנֵי יְהוָה פֶּתַח אֹהֶל מוֹעֵד׃
וְלָקַחְתָּ מִדַּם הַפָּר וְנָתַתָּה עַל־קַרְנֹת הַמִּזְבֵּחַ בְּאֶצְבָּעֶךָ וְאֶת־כָּל־הַדָּם תִּשְׁפֹּךְ אֶל־יְסוֹד הַמִּזְבֵּחַ׃
וְלָקַחְתָּ אֶת־כָּל־הַחֵלֶב הַמְכַסֶּה אֶת־הַקֶּרֶב וְאֵת הַיֹּתֶרֶת עַל־הַכָּבֵד וְאֵת שְׁתֵּי הַכְּלָיֹת וְאֶת־הַחֵלֶב אֲשֶׁר עֲלֵיהֶן וְהִקְטַרְתָּ הַמִּזְבֵּחָה׃
וְאֶת־בְּשַׂר הַפָּר וְאֶת־עֹרוֹ וְאֶת־פִּרְשׁוֹ תִּשְׂרֹף בָּאֵשׁ מִחוּץ לַמַּחֲנֶה חַטָּאת הוּא׃
וְאֶת־הָאַיִל הָאֶחָד תִּקָּח וְסָמְכוּ אַהֲרֹן וּבָנָיו אֶת־יְדֵיהֶם עַל־רֹאשׁ הָאָיִל׃
וְשָׁחַטְתָּ אֶת־הָאָיִל וְלָקַחְתָּ אֶת־דָּמוֹ וְזָרַקְתָּ עַל־הַמִּזְבֵּחַ סָבִיב׃
וְאֶת־הָאַיִל תְּנַתֵּחַ לִנְתָחָיו וְרָחַצְתָּ קִרְבּוֹ וּכְרָעָיו וְנָתַתָּ עַל־נְתָחָיו וְעַל־רֹאשׁוֹ׃
וְהִקְטַרְתָּ אֶת־כָּל־הָאַיִל הַמִּזְבֵּחָה עֹלָה הוּא לַיהוָה רֵיחַ נִיחוֹחַ אִשֶּׁה לַיהוָה הוּא׃
וְלָקַחְתָּ אֵת הָאַיִל הַשֵּׁנִי וְסָמַךְ אַהֲרֹן וּבָנָיו אֶת־יְדֵיהֶם עַל־רֹאשׁ הָאָיִל׃
וְשָׁחַטְתָּ אֶת־הָאַיִל וְלָקַחְתָּ מִדָּמוֹ וְנָתַתָּה עַל־תְּנוּךְ אֹזֶן אַהֲרֹן וְעַל־תְּנוּךְ אֹזֶן בָּנָיו הַיְמָנִית וְעַל־בֹּהֶן יָדָם הַיְמָנִית וְעַל־בֹּהֶן רַגְלָם הַיְמָנִית וְזָרַקְתָּ אֶת־הַדָּם עַל־הַמִּזְבֵּחַ סָבִיב׃
וְלָקַחְתָּ מִן־הַדָּם אֲשֶׁר עַל־הַמִּזְבֵּחַ וּמִשֶּׁמֶן הַמִּשְׁחָה וְהִזֵּיתָ עַל־אַהֲרֹן וְעַל־בְּגָדָיו וְעַל־בָּנָיו וְעַל־בִּגְדֵי בָנָיו אִתּוֹ וְקָדַשׁ הוּא וּבְגָדָיו וּבָנָיו וּבִגְדֵי בָנָיו אִתּוֹ׃
וְלָקַחְתָּ מִן־הָאַיִל הַחֵלֶב וְהָאַלְיָה וְאֶת־הַחֵלֶב הַמְכַסֶּה אֶת־הַקֶּרֶב וְאֵת יֹתֶרֶת הַכָּבֵד וְאֵת שְׁתֵּי הַכְּלָיֹת וְאֶת־הַחֵלֶב אֲשֶׁר עֲלֵהֶן וְאֵת שׁוֹק הַיָּמִין כִּי אֵיל מִלֻּאִים הוּא׃
וְכִכַּר לֶחֶם אַחַת וַחַלַּת לֶחֶם שֶׁמֶן אַחַת וְרָקִיק אֶחָד מִסַּל הַמַּצּוֹת אֲשֶׁר לִפְנֵי יְהוָה׃
וְשַׂמְתָּ הַכֹּל עַל כַּפֵּי אַהֲרֹן וְעַל כַּפֵּי בָנָיו וְהֵנַפְתָּ אֹתָם תְּנוּפָה לִפְנֵי יְהוָה׃
וְלָקַחְתָּ אֹתָם מִיָּדָם וְהִקְטַרְתָּ הַמִּזְבֵּחָה עַל־הָעֹלָה לְרֵיחַ נִיחוֹחַ לִפְנֵי יְהוָה אִשֶּׁה הוּא לַיהוָה׃
וְלָקַחְתָּ אֶת־הֶחָזֶה מֵאֵיל הַמִּלֻּאִים אֲשֶׁר לְאַהֲרֹן וְהֵנַפְתָּ אֹתוֹ תְּנוּפָה לִפְנֵי יְהוָה וְהָיָה לְךָ לְמָנָה׃
וְקִדַּשְׁתָּ אֵת חֲזֵה הַתְּנוּפָה וְאֵת שׁוֹק הַתְּרוּמָה אֲשֶׁר הוּנַף וַאֲשֶׁר הוּרָם מֵאֵיל הַמִּלֻּאִים מֵאֲשֶׁר לְאַהֲרֹן וּמֵאֲשֶׁר לְבָנָיו׃
וְהָיָה לְאַהֲרֹן וּלְבָנָיו לְחָק־עוֹלָם מֵאֵת בְּנֵי יִשְׂרָאֵל כִּי תְרוּמָה הוּא וּתְרוּמָה יִהְיֶה מֵאֵת בְּנֵי־יִשְׂרָאֵל מִזִּבְחֵי שַׁלְמֵיהֶם תְּרוּמָתָם לַיהוָה׃
וּבִגְדֵי הַקֹּדֶשׁ אֲשֶׁר לְאַהֲרֹן יִהְיוּ לְבָנָיו אַחֲרָיו לְמָשְׁחָה בָהֶם וּלְמַלֵּא־בָם אֶת־יָדָם׃
שִׁבְעַת יָמִים יִלְבָּשָׁם הַכֹּהֵן תַּחְתָּיו מִבָּנָיו אֲשֶׁר יָבֹא אֶל־אֹהֶל מוֹעֵד לְשָׁרֵת בַּקֹּדֶשׁ׃
וְאֵת אֵיל הַמִּלֻּאִים תִּקָּח וּבִשַּׁלְתָּ אֶת־בְּשָׂרוֹ בְּמָקֹם קָדֹשׁ׃
וְאָכַל אַהֲרֹן וּבָנָיו אֶת־בְּשַׂר הָאַיִל וְאֶת־הַלֶּחֶם אֲשֶׁר בַּסָּל פֶּתַח אֹהֶל מוֹעֵד׃
וְאָכְלוּ אֹתָם אֲשֶׁר כֻּפַּר בָּהֶם לְמַלֵּא אֶת־יָדָם לְקַדֵּשׁ אֹתָם וְזָר לֹא־יֹאכַל כִּי־קֹדֶשׁ הֵם׃
וְאִם־יִוָּתֵר מִבְּשַׂר הַמִּלֻּאִים וּמִן־הַלֶּחֶם עַד־הַבֹּקֶר וְשָׂרַפְתָּ אֶת־הַנּוֹתָר בָּאֵשׁ לֹא יֵאָכֵל כִּי־קֹדֶשׁ הוּא׃
וְעָשִׂיתָ לְאַהֲרֹן וּלְבָנָיו כָּכָה כְּכֹל אֲשֶׁר־צִוִּיתִי אֹתָכָה שִׁבְעַת יָמִים תְּמַלֵּא יָדָם׃
וּפַר חַטָּאת תַּעֲשֶׂה לַיּוֹם עַל־הַכִּפֻּרִים וְחִטֵּאתָ עַל־הַמִּזְבֵּחַ בְּכַפֶּרְךָ עָלָיו וּמָשַׁחְתָּ אֹתוֹ לְקַדְּשׁוֹ׃
שִׁבְעַת יָמִים תְּכַפֵּר עַל־הַמִּזְבֵּחַ וְקִדַּשְׁתָּ אֹתוֹ וְהָיָה הַמִּזְבֵּחַ קֹדֶשׁ קָדָשִׁים כָּל־הַנֹּגֵעַ בַּמִּזְבֵּחַ יִקְדָּשׁ׃
וְזֶה אֲשֶׁר תַּעֲשֶׂה עַל־הַמִּזְבֵּחַ כְּבָשִׂים בְּנֵי־שָׁנָה שְׁנַיִם לַיּוֹם תָּמִיד׃
אֶת־הַכֶּבֶשׂ הָאֶחָד תַּעֲשֶׂה בַבֹּקֶר וְאֵת הַכֶּבֶשׂ הַשֵּׁנִי תַּעֲשֶׂה בֵּין הָעַרְבָּיִם׃
וְעִשָּׂרֹן סֹלֶת בָּלוּל בְּשֶׁמֶן כָּתִית רֶבַע הַהִין וְנֵסֶךְ רְבִעִית הַהִין יָיִן לַכֶּבֶשׂ הָאֶחָד׃
וְאֵת הַכֶּבֶשׂ הַשֵּׁנִי תַּעֲשֶׂה בֵּין הָעַרְבָּיִם כְּמִנְחַת הַבֹּקֶר וּכְנִסְכָּהּ תַּעֲשֶׂה־לָּהּ לְרֵיחַ נִיחֹחַ אִשֶּׁה לַיהוָה׃
עֹלַת תָּמִיד לְדֹרֹתֵיכֶם פֶּתַח אֹהֶל־מוֹעֵד לִפְנֵי יְהוָה אֲשֶׁר אִוָּעֵד לָכֶם שָׁמָּה לְדַבֵּר אֵלֶיךָ שָׁם׃
וְנֹעַדְתִּי שָׁמָּה לִבְנֵי יִשְׂרָאֵל וְנִקְדַּשׁ בִּכְבֹדִי׃
וְקִדַּשְׁתִּי אֶת־אֹהֶל מוֹעֵד וְאֶת־הַמִּזְבֵּחַ וְאֶת־אַהֲרֹן וְאֶת־בָּנָיו אֲקַדֵּשׁ לְכַהֵן לִי׃
וְשָׁכַנְתִּי בְּתוֹךְ בְּנֵי יִשְׂרָאֵל וְהָיִיתִי לָהֶם לֵאלֹהִים׃
וְיָדְעוּ כִּי אֲנִי יְהוָה אֱלֹהֵיהֶם אֲשֶׁר הוֹצֵאתִי אֹתָם מֵאֶרֶץ מִצְרַיִם לְשָׁכְנִי בְתוֹכָם אֲנִי יְהוָה אֱלֹהֵיהֶם׃

Chapter 30

וְעָשִׂיתָ מִזְבֵּחַ מִקְטַר קְטֹרֶת עֲצֵי שִׁטִּים תַּעֲשֶׂה אֹתוֹ׃
אַמָּה אָרְכּוֹ וְאַמָּה רָחְבּוֹ רָבוּעַ יִהְיֶה וְאַמָּתַיִם קֹמָתוֹ מִמֶּנּוּ קַרְנֹתָיו׃
וְצִפִּיתָ אֹתוֹ זָהָב טָהוֹר אֶת־גַּגּוֹ וְאֶת־קִירֹתָיו סָבִיב וְאֶת־קַרְנֹתָיו וְעָשִׂיתָ לּוֹ זֵר זָהָב סָבִיב׃
וּשְׁתֵּי טַבְּעֹת זָהָב תַּעֲשֶׂה־לּוֹ מִתַּחַת לְזֵרוֹ עַל שְׁתֵּי צַלְעֹתָיו תַּעֲשֶׂה עַל־שְׁנֵי צִדָּיו וְהָיָה לְבָתִּים לְבַדִּים לָשֵׂאת אֹתוֹ בָּהֵמָּה׃
וְעָשִׂיתָ אֶת־הַבַּדִּים עֲצֵי שִׁטִּים וְצִפִּיתָ אֹתָם זָהָב׃
וְנָתַתָּה אֹתוֹ לִפְנֵי הַפָּרֹכֶת אֲשֶׁר עַל־אֲרֹן הָעֵדֻת לִפְנֵי הַכַּפֹּרֶת אֲשֶׁר עַל־הָעֵדֻת אֲשֶׁר אִוָּעֵד לְךָ שָׁמָּה׃
וְהִקְטִיר עָלָיו אַהֲרֹן קְטֹרֶת סַמִּים בַּבֹּקֶר בַּבֹּקֶר בְּהֵיטִיבוֹ אֶת־הַנֵּרֹת יַקְטִירֶנָּה׃
וּבְהַעֲלֹת אַהֲרֹן אֶת־הַנֵּרֹת בֵּין הָעֲרְבַּיִם יַקְטִירֶנָּה קְטֹרֶת תָּמִיד לִפְנֵי יְהוָה לְדֹרֹתֵיכֶם׃
לֹא־תַעֲלוּ עָלָיו קְטֹרֶת זָרָה וְעֹלָה וּמִנְחָה וְנֵסֶךְ לֹא תִסְּכוּ עָלָיו׃
וְכִפֶּר אַהֲרֹן עַל־קַרְנֹתָיו אַחַת בַּשָּׁנָה מִדַּם חַטַּאת הַכִּפֻּרִים אַחַת בַּשָּׁנָה יְכַפֵּר עָלָיו לְדֹרֹתֵיכֶם קֹדֶשׁ־קָדָשִׁים הוּא לַיהוָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
כִּי תִשָּׂא אֶת־רֹאשׁ בְּנֵי־יִשְׂרָאֵל לִפְקֻדֵיהֶם וְנָתְנוּ אִישׁ כֹּפֶר נַפְשׁוֹ לַיהוָה בִּפְקֹד אֹתָם וְלֹא־יִהְיֶה בָהֶם נֶגֶף בִּפְקֹד אֹתָם׃
זֶה יִתְּנוּ כָּל־הָעֹבֵר עַל־הַפְּקֻדִים מַחֲצִית הַשֶּׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ עֶשְׂרִים גֵּרָה הַשֶּׁקֶל מַחֲצִית הַשֶּׁקֶל תְּרוּמָה לַיהוָה׃
כֹּל הָעֹבֵר עַל־הַפְּקֻדִים מִבֶּן עֶשְׂרִים שָׁנָה וָמָעְלָה יִתֵּן תְּרוּמַת יְהוָה׃
הֶעָשִׁיר לֹא־יַרְבֶּה וְהַדַּל לֹא יַמְעִיט מִמַּחֲצִית הַשָּׁקֶל לָתֵת אֶת־תְּרוּמַת יְהוָה לְכַפֵּר עַל־נַפְשֹׁתֵיכֶם׃
וְלָקַחְתָּ אֶת־כֶּסֶף הַכִּפֻּרִים מֵאֵת בְּנֵי יִשְׂרָאֵל וְנָתַתָּ אֹתוֹ עַל־עֲבֹדַת אֹהֶל מוֹעֵד וְהָיָה לִבְנֵי יִשְׂרָאֵל לְזִכָּרוֹן לִפְנֵי יְהוָה לְכַפֵּר עַל־נַפְשֹׁתֵיכֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
וְעָשִׂיתָ כִּיּוֹר נְחֹשֶׁת וְכַנּוֹ נְחֹשֶׁת לְרָחְצָה וְנָתַתָּ אֹתוֹ בֵּין־אֹהֶל מוֹעֵד וּבֵין הַמִּזְבֵּחַ וְנָתַתָּ שָׁמָּה מָיִם׃
וְרָחֲצוּ אַהֲרֹן וּבָנָיו מִמֶּנּוּ אֶת־יְדֵיהֶם וְאֶת־רַגְלֵיהֶם׃
בְּבֹאָם אֶל־אֹהֶל מוֹעֵד יִרְחֲצוּ־מַיִם וְלֹא יָמֻתוּ אוֹ בְגִשְׁתָּם אֶל־הַמִּזְבֵּחַ לְשָׁרֵת לְהַקְטִיר אִשֶּׁה לַיהוָה׃
וְרָחֲצוּ יְדֵיהֶם וְרַגְלֵיהֶם וְלֹא יָמֻתוּ וְהָיְתָה לָהֶם חָק־עוֹלָם לוֹ וּלְזַרְעוֹ לְדֹרֹתָם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
וְאַתָּה קַח־לְךָ בְּשָׂמִים רֹאשׁ מָר־דְּרוֹר חֲמֵשׁ מֵאוֹת וְקִנְּמָן־בֶּשֶׂם מַחֲצִיתוֹ חֲמִשִּׁים וּמָאתָיִם וּקְנֵה־בֹשֶׂם חֲמִשִּׁים וּמָאתָיִם׃
וְקִדָּה חֲמֵשׁ מֵאוֹת בְּשֶׁקֶל הַקֹּדֶשׁ וְשֶׁמֶן זַיִת הִין׃
וְעָשִׂיתָ אֹתוֹ שֶׁמֶן מִשְׁחַת־קֹדֶשׁ רֹקַח מִרְקַחַת מַעֲשֵׂה רֹקֵחַ שֶׁמֶן מִשְׁחַת־קֹדֶשׁ יִהְיֶה׃
וּמָשַׁחְתָּ בוֹ אֶת־אֹהֶל מוֹעֵד וְאֵת אֲרוֹן הָעֵדֻת׃
וְאֶת־הַשֻּׁלְחָן וְאֶת־כָּל־כֵּלָיו וְאֶת־הַמְּנֹרָה וְאֶת־כֵּלֶיהָ וְאֵת מִזְבַּח הַקְּטֹרֶת׃
וְאֶת־מִזְבַּח הָעֹלָה וְאֶת־כָּל־כֵּלָיו וְאֶת־הַכִּיֹּר וְאֶת־כַּנּוֹ׃
וְקִדַּשְׁתָּ אֹתָם וְהָיוּ קֹדֶשׁ קָדָשִׁים כָּל־הַנֹּגֵעַ בָּהֶם יִקְדָּשׁ׃
וְאֶת־אַהֲרֹן וְאֶת־בָּנָיו תִּמְשָׁח וְקִדַּשְׁתָּ אֹתָם לְכַהֵן לִי׃
וְאֶל־בְּנֵי יִשְׂרָאֵל תְּדַבֵּר לֵאמֹר שֶׁמֶן מִשְׁחַת־קֹדֶשׁ יִהְיֶה זֶה לִי לְדֹרֹתֵיכֶם׃
עַל־בְּשַׂר אָדָם לֹא יִיסָךְ וּבְמַתְכֻּנְתּוֹ לֹא תַעֲשׂוּ כָּמֹהוּ קֹדֶשׁ הוּא קֹדֶשׁ יִהְיֶה לָכֶם׃
אִישׁ אֲשֶׁר יִרְקַח כָּמֹהוּ וַאֲשֶׁר יִתֵּן מִמֶּנּוּ עַל־זָר וְנִכְרַת מֵעַמָּיו׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה קַח־לְךָ סַמִּים נָטָף וּשְׁחֵלֶת וְחֶלְבְּנָה סַמִּים וּלְבֹנָה זַכָּה בַּד בְּבַד יִהְיֶה׃
וְעָשִׂיתָ אֹתָהּ קְטֹרֶת רֹקַח מַעֲשֵׂה רוֹקֵחַ מְמֻלָּח טָהוֹר קֹדֶשׁ׃
וְשָׁחַקְתָּ מִמֶּנָּה הָדֵק וְנָתַתָּה מִמֶּנָּה לִפְנֵי הָעֵדֻת בְּאֹהֶל מוֹעֵד אֲשֶׁר אִוָּעֵד לְךָ שָׁמָּה קֹדֶשׁ קָדָשִׁים תִּהְיֶה לָכֶם׃
וְהַקְּטֹרֶת אֲשֶׁר תַּעֲשֶׂה בְּמַתְכֻּנְתָּהּ לֹא תַעֲשׂוּ לָכֶם קֹדֶשׁ תִּהְיֶה לְךָ לַיהוָה׃
אִישׁ אֲשֶׁר־יַעֲשֶׂה כָמוֹהָ לְהָרִיחַ בָּהּ וְנִכְרַת מֵעַמָּיו׃

Chapter 31

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
רְאֵה קָרָאתִי בְשֵׁם בְּצַלְאֵל בֶּן־אוּרִי בֶן־חוּר לְמַטֵּה יְהוּדָה׃
וָאֲמַלֵּא אֹתוֹ רוּחַ אֱלֹהִים בְּחָכְמָה וּבִתְבוּנָה וּבְדַעַת וּבְכָל־מְלָאכָה׃
לַחְשֹׁב מַחֲשָׁבֹת לַעֲשׂוֹת בַּזָּהָב וּבַכֶּסֶף וּבַנְּחֹשֶׁת׃
וּבַחֲרֹשֶׁת אֶבֶן לְמַלֹּאת וּבַחֲרֹשֶׁת עֵץ לַעֲשׂוֹת בְּכָל־מְלָאכָה׃
וַאֲנִי הִנֵּה נָתַתִּי אִתּוֹ אֵת אָהֳלִיאָב בֶּן־אֲחִיסָמָךְ לְמַטֵּה־דָן וּבְלֵב כָּל־חֲכַם־לֵב נָתַתִּי חָכְמָה וְעָשׂוּ אֵת כָּל־אֲשֶׁר צִוִּיתִךָ׃
אֵת אֹהֶל מוֹעֵד וְאֶת־הָאָרֹן לָעֵדֻת וְאֶת־הַכַּפֹּרֶת אֲשֶׁר עָלָיו וְאֵת כָּל־כְּלֵי הָאֹהֶל׃
וְאֶת־הַשֻּׁלְחָן וְאֶת־כֵּלָיו וְאֶת־הַמְּנֹרָה הַטְּהֹרָה וְאֶת־כָּל־כֵּלֶיהָ וְאֵת מִזְבַּח הַקְּטֹרֶת׃
וְאֶת־מִזְבַּח הָעֹלָה וְאֶת־כָּל־כֵּלָיו וְאֶת־הַכִּיּוֹר וְאֶת־כַּנּוֹ׃
וְאֵת בִּגְדֵי הַשְּׂרָד וְאֶת־בִּגְדֵי הַקֹּדֶשׁ לְאַהֲרֹן הַכֹּהֵן וְאֶת־בִּגְדֵי בָנָיו לְכַהֵן׃
וְאֵת שֶׁמֶן הַמִּשְׁחָה וְאֶת־קְטֹרֶת הַסַּמִּים לַקֹּדֶשׁ כְּכֹל אֲשֶׁר־צִוִּיתִךָ יַעֲשׂוּ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
וְאַתָּה דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר אַךְ אֶת־שַׁבְּתֹתַי תִּשְׁמֹרוּ כִּי אוֹת הִוא בֵּינִי וּבֵינֵיכֶם לְדֹרֹתֵיכֶם לָדַעַת כִּי אֲנִי יְהוָה מְקַדִּשְׁכֶם׃
וּשְׁמַרְתֶּם אֶת־הַשַּׁבָּת כִּי קֹדֶשׁ הִוא לָכֶם מְחַלְלֶיהָ מוֹת יוּמָת כִּי כָּל־הָעֹשֶׂה בָהּ מְלָאכָה וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מִקֶּרֶב עַמֶּיהָ׃
שֵׁשֶׁת יָמִים יֵעָשֶׂה מְלָאכָה וּבַיּוֹם הַשְּׁבִיעִי שַׁבַּת שַׁבָּתוֹן קֹדֶשׁ לַיהוָה כָּל־הָעֹשֶׂה מְלָאכָה בְּיוֹם הַשַּׁבָּת מוֹת יוּמָת׃
וְשָׁמְרוּ בְנֵי־יִשְׂרָאֵל אֶת־הַשַּׁבָּת לַעֲשׂוֹת אֶת־הַשַּׁבָּת לְדֹרֹתָם בְּרִית עוֹלָם׃
בֵּינִי וּבֵין בְּנֵי יִשְׂרָאֵל אוֹת הִוא לְעֹלָם כִּי־שֵׁשֶׁת יָמִים עָשָׂה יְהוָה אֶת־הַשָּׁמַיִם וְאֶת־הָאָרֶץ וּבַיּוֹם הַשְּׁבִיעִי שָׁבַת וַיִּנָּפַשׁ׃
וַיִּתֵּן אֶל־מֹשֶׁה כְּכַלֹּתוֹ לְדַבֵּר אִתּוֹ בְּהַר סִינַי שְׁנֵי לֻחֹת הָעֵדֻת לֻחֹת אֶבֶן כְּתֻבִים בְּאֶצְבַּע אֱלֹהִים׃

Chapter 32

וַיַּרְא הָעָם כִּי־בֹשֵׁשׁ מֹשֶׁה לָרֶדֶת מִן־הָהָר וַיִּקָּהֵל הָעָם עַל־אַהֲרֹן וַיֹּאמְרוּ אֵלָיו קוּם עֲשֵׂה־לָנוּ אֱלֹהִים אֲשֶׁר יֵלְכוּ לְפָנֵינוּ כִּי־זֶה מֹשֶׁה הָאִישׁ אֲשֶׁר הֶעֱלָנוּ מֵאֶרֶץ מִצְרַיִם לֹא יָדַעְנוּ מֶה־הָיָה לוֹ׃
וַיֹּאמֶר אֲלֵהֶם אַהֲרֹן פָּרְקוּ נִזְמֵי הַזָּהָב אֲשֶׁר בְּאָזְנֵי נְשֵׁיכֶם בְּנֵיכֶם וּבְנֹתֵיכֶם וְהָבִיאוּ אֵלָי׃
וַיִּתְפָּרְקוּ כָּל־הָעָם אֶת־נִזְמֵי הַזָּהָב אֲשֶׁר בְּאָזְנֵיהֶם וַיָּבִיאוּ אֶל־אַהֲרֹן׃
וַיִּקַּח מִיָּדָם וַיָּצַר אֹתוֹ בַּחֶרֶט וַיַּעֲשֵׂהוּ עֵגֶל מַסֵּכָה וַיֹּאמְרוּ אֵלֶּה אֱלֹהֶיךָ יִשְׂרָאֵל אֲשֶׁר הֶעֱלוּךָ מֵאֶרֶץ מִצְרָיִם׃
וַיַּרְא אַהֲרֹן וַיִּבֶן מִזְבֵּחַ לְפָנָיו וַיִּקְרָא אַהֲרֹן וַיֹּאמַר חַג לַיהוָה מָחָר׃
וַיַּשְׁכִּימוּ מִמָּחֳרָת וַיַּעֲלוּ עֹלֹת וַיַּגִּשׁוּ שְׁלָמִים וַיֵּשֶׁב הָעָם לֶאֱכֹל וְשָׁתוֹ וַיָּקֻמוּ לְצַחֵק׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֶךְ־רֵד כִּי שִׁחֵת עַמְּךָ אֲשֶׁר הֶעֱלֵיתָ מֵאֶרֶץ מִצְרָיִם׃
סָרוּ מַהֵר מִן־הַדֶּרֶךְ אֲשֶׁר צִוִּיתִם עָשׂוּ לָהֶם עֵגֶל מַסֵּכָה וַיִּשְׁתַּחֲווּ־לוֹ וַיִּזְבְּחוּ־לוֹ וַיֹּאמְרוּ אֵלֶּה אֱלֹהֶיךָ יִשְׂרָאֵל אֲשֶׁר הֶעֱלוּךָ מֵאֶרֶץ מִצְרָיִם׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה רָאִיתִי אֶת־הָעָם הַזֶּה וְהִנֵּה עַם־קְשֵׁה־עֹרֶף הוּא׃
וְעַתָּה הַנִּיחָה לִּי וְיִחַר־אַפִּי בָהֶם וַאֲכַלֵּם וְאֶעֱשֶׂה אוֹתְךָ לְגוֹי גָּדוֹל׃
וַיְחַל מֹשֶׁה אֶת־פְּנֵי יְהוָה אֱלֹהָיו וַיֹּאמֶר לָמָה יְהוָה יֶחֱרֶה אַפְּךָ בְּעַמֶּךָ אֲשֶׁר הוֹצֵאתָ מֵאֶרֶץ מִצְרַיִם בְּכֹחַ גָּדוֹל וּבְיָד חֲזָקָה׃
לָמָּה יֹאמְרוּ מִצְרַיִם לֵאמֹר בְּרָעָה הוֹצִיאָם לַהֲרֹג אֹתָם בֶּהָרִים וּלְכַלֹּתָם מֵעַל פְּנֵי הָאֲדָמָה שׁוּב מֵחֲרוֹן אַפֶּךָ וְהִנָּחֵם עַל־הָרָעָה לְעַמֶּךָ׃
זְכֹר לְאַבְרָהָם לְיִצְחָק וּלְיִשְׂרָאֵל עֲבָדֶיךָ אֲשֶׁר נִשְׁבַּעְתָּ לָהֶם בָּךְ וַתְּדַבֵּר אֲלֵהֶם אַרְבֶּה אֶת־זַרְעֲכֶם כְּכוֹכְבֵי הַשָּׁמָיִם וְכָל־הָאָרֶץ הַזֹּאת אֲשֶׁר אָמַרְתִּי אֶתֵּן לְזַרְעֲכֶם וְנָחֲלוּ לְעֹלָם׃
וַיִּנָּחֶם יְהוָה עַל־הָרָעָה אֲשֶׁר דִּבֶּר לַעֲשׂוֹת לְעַמּוֹ׃
וַיִּפֶן וַיֵּרֶד מֹשֶׁה מִן־הָהָר וּשְׁנֵי לֻחֹת הָעֵדֻת בְּיָדוֹ לֻחֹת כְּתֻבִים מִשְּׁנֵי עֶבְרֵיהֶם מִזֶּה וּמִזֶּה הֵם כְּתֻבִים׃
וְהַלֻּחֹת מַעֲשֵׂה אֱלֹהִים הֵמָּה וְהַמִּכְתָּב מִכְתַּב אֱלֹהִים הוּא חָרוּת עַל־הַלֻּחֹת׃
וַיִּשְׁמַע יְהוֹשֻׁעַ אֶת־קוֹל הָעָם בְּרֵעֹה וַיֹּאמֶר אֶל־מֹשֶׁה קוֹל מִלְחָמָה בַּמַּחֲנֶה׃
וַיֹּאמֶר אֵין קוֹל עֲנוֹת גְּבוּרָה וְאֵין קוֹל עֲנוֹת חֲלוּשָׁה קוֹל עַנּוֹת אָנֹכִי שֹׁמֵעַ׃
וַיְהִי כַּאֲשֶׁר קָרַב אֶל־הַמַּחֲנֶה וַיַּרְא אֶת־הָעֵגֶל וּמְחֹלֹת וַיִּחַר־אַף מֹשֶׁה וַיַּשְׁלֵךְ מידו [מִיָּדָיו] אֶת־הַלֻּחֹת וַיְשַׁבֵּר אֹתָם תַּחַת הָהָר׃
וַיִּקַּח אֶת־הָעֵגֶל אֲשֶׁר עָשׂוּ וַיִּשְׂרֹף בָּאֵשׁ וַיִּטְחַן עַד אֲשֶׁר־דָּק וַיִּזֶר עַל־פְּנֵי הַמַּיִם וַיַּשְׁקְ אֶת־בְּנֵי יִשְׂרָאֵל׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן מֶה־עָשָׂה לְךָ הָעָם הַזֶּה כִּי־הֵבֵאתָ עָלָיו חֲטָאָה גְדֹלָה׃
וַיֹּאמֶר אַהֲרֹן אַל־יִחַר אַף אֲדֹנִי אַתָּה יָדַעְתָּ אֶת־הָעָם כִּי בְרָע הוּא׃
וַיֹּאמְרוּ לִי עֲשֵׂה־לָנוּ אֱלֹהִים אֲשֶׁר יֵלְכוּ לְפָנֵינוּ כִּי־זֶה מֹשֶׁה הָאִישׁ אֲשֶׁר הֶעֱלָנוּ מֵאֶרֶץ מִצְרַיִם לֹא יָדַעְנוּ מֶה־הָיָה לוֹ׃
וָאֹמַר לָהֶם לְמִי זָהָב הִתְפָּרָקוּ וַיִּתְּנוּ־לִי וָאַשְׁלִכֵהוּ בָאֵשׁ וַיֵּצֵא הָעֵגֶל הַזֶּה׃
וַיַּרְא מֹשֶׁה אֶת־הָעָם כִּי פָרֻעַ הוּא כִּי־פְרָעֹה אַהֲרֹן לְשִׁמְצָה בְּקָמֵיהֶם׃
וַיַּעֲמֹד מֹשֶׁה בְּשַׁעַר הַמַּחֲנֶה וַיֹּאמֶר מִי לַיהוָה אֵלָי וַיֵּאָסְפוּ אֵלָיו כָּל־בְּנֵי לֵוִי׃
וַיֹּאמֶר לָהֶם כֹּה־אָמַר יְהוָה אֱלֹהֵי יִשְׂרָאֵל שִׂימוּ אִישׁ־חַרְבּוֹ עַל־יְרֵכוֹ עִבְרוּ וָשׁוּבוּ מִשַּׁעַר לָשַׁעַר בַּמַּחֲנֶה וְהִרְגוּ אִישׁ־אֶת־אָחִיו וְאִישׁ אֶת־רֵעֵהוּ וְאִישׁ אֶת־קְרֹבוֹ׃
וַיַּעֲשׂוּ בְנֵי־לֵוִי כִּדְבַר מֹשֶׁה וַיִּפֹּל מִן־הָעָם בַּיּוֹם הַהוּא כִּשְׁלֹשֶׁת אַלְפֵי אִישׁ׃
וַיֹּאמֶר מֹשֶׁה מִלְאוּ יֶדְכֶם הַיּוֹם לַיהוָה כִּי אִישׁ בִּבְנוֹ וּבְאָחִיו וְלָתֵת עֲלֵיכֶם הַיּוֹם בְּרָכָה׃
וַיְהִי מִמָּחֳרָת וַיֹּאמֶר מֹשֶׁה אֶל־הָעָם אַתֶּם חֲטָאתֶם חֲטָאָה גְדֹלָה וְעַתָּה אֶעֱלֶה אֶל־יְהוָה אוּלַי אֲכַפְּרָה בְּעַד חַטַּאתְכֶם׃
וַיָּשָׁב מֹשֶׁה אֶל־יְהוָה וַיֹּאמַר אָנָּא חָטָא הָעָם הַזֶּה חֲטָאָה גְדֹלָה וַיַּעֲשׂוּ לָהֶם אֱלֹהֵי זָהָב׃
וְעַתָּה אִם־תִּשָּׂא חַטָּאתָם וְאִם־אַיִן מְחֵנִי נָא מִסִּפְרְךָ אֲשֶׁר כָּתָבְתָּ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה מִי אֲשֶׁר חָטָא־לִי אֶמְחֶנּוּ מִסִּפְרִי׃
וְעַתָּה לֵךְ נְחֵה אֶת־הָעָם אֶל אֲשֶׁר־דִּבַּרְתִּי לָךְ הִנֵּה מַלְאָכִי יֵלֵךְ לְפָנֶיךָ וּבְיוֹם פָּקְדִי וּפָקַדְתִּי עֲלֵיהֶם חַטָּאתָם׃
וַיִּגֹּף יְהוָה אֶת־הָעָם עַל אֲשֶׁר עָשׂוּ אֶת־הָעֵגֶל אֲשֶׁר עָשָׂה אַהֲרֹן׃

Chapter 33

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵךְ עֲלֵה מִזֶּה אַתָּה וְהָעָם אֲשֶׁר הֶעֱלִיתָ מֵאֶרֶץ מִצְרָיִם אֶל־הָאָרֶץ אֲשֶׁר נִשְׁבַּעְתִּי לְאַבְרָהָם לְיִצְחָק וּלְיַעֲקֹב לֵאמֹר לְזַרְעֲךָ אֶתְּנֶנָּה׃
וְשָׁלַחְתִּי לְפָנֶיךָ מַלְאָךְ וְגֵרַשְׁתִּי אֶת־הַכְּנַעֲנִי הָאֱמֹרִי וְהַחִתִּי וְהַפְּרִזִּי הַחִוִּי וְהַיְבוּסִי׃
אֶל־אֶרֶץ זָבַת חָלָב וּדְבָשׁ כִּי לֹא אֶעֱלֶה בְּקִרְבְּךָ כִּי עַם־קְשֵׁה־עֹרֶף אַתָּה פֶּן־אֲכֶלְךָ בַּדָּרֶךְ׃
וַיִּשְׁמַע הָעָם אֶת־הַדָּבָר הָרָע הַזֶּה וַיִּתְאַבָּלוּ וְלֹא־שָׁתוּ אִישׁ עֶדְיוֹ עָלָיו׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה אֱמֹר אֶל־בְּנֵי־יִשְׂרָאֵל אַתֶּם עַם־קְשֵׁה־עֹרֶף רֶגַע אֶחָד אֶעֱלֶה בְקִרְבְּךָ וְכִלִּיתִיךָ וְעַתָּה הוֹרֵד עֶדְיְךָ מֵעָלֶיךָ וְאֵדְעָה מָה אֶעֱשֶׂה־לָּךְ׃
וַיִּתְנַצְּלוּ בְנֵי־יִשְׂרָאֵל אֶת־עֶדְיָם מֵהַר חוֹרֵב׃
וּמֹשֶׁה יִקַּח אֶת־הָאֹהֶל וְנָטָה־לוֹ מִחוּץ לַמַּחֲנֶה הַרְחֵק מִן־הַמַּחֲנֶה וְקָרָא לוֹ אֹהֶל מוֹעֵד וְהָיָה כָּל־מְבַקֵּשׁ יְהוָה יֵצֵא אֶל־אֹהֶל מוֹעֵד אֲשֶׁר מִחוּץ לַמַּחֲנֶה׃
וְהָיָה כְּצֵאת מֹשֶׁה אֶל־הָאֹהֶל יָקוּמוּ כָּל־הָעָם וְנִצְּבוּ אִישׁ פֶּתַח אָהֳלוֹ וְהִבִּיטוּ אַחֲרֵי מֹשֶׁה עַד־בֹּאוֹ הָאֹהֱלָה׃
וְהָיָה כְּבֹא מֹשֶׁה הָאֹהֱלָה יֵרֵד עַמּוּד הֶעָנָן וְעָמַד פֶּתַח הָאֹהֶל וְדִבֶּר עִם־מֹשֶׁה׃
וְרָאָה כָל־הָעָם אֶת־עַמּוּד הֶעָנָן עֹמֵד פֶּתַח הָאֹהֶל וְקָם כָּל־הָעָם וְהִשְׁתַּחֲוּוּ אִישׁ פֶּתַח אָהֳלוֹ׃
וְדִבֶּר יְהוָה אֶל־מֹשֶׁה פָּנִים אֶל־פָּנִים כַּאֲשֶׁר יְדַבֵּר אִישׁ אֶל־רֵעֵהוּ וְשָׁב אֶל־הַמַּחֲנֶה וּמְשָׁרְתוֹ יְהוֹשֻׁעַ בִּן־נוּן נַעַר לֹא יָמִישׁ מִתּוֹךְ הָאֹהֶל׃
וַיֹּאמֶר מֹשֶׁה אֶל־יְהוָה רְאֵה אַתָּה אֹמֵר אֵלַי הַעַל אֶת־הָעָם הַזֶּה וְאַתָּה לֹא הוֹדַעְתַּנִי אֵת אֲשֶׁר־תִּשְׁלַח עִמִּי וְאַתָּה אָמַרְתָּ יְדַעְתִּיךָ בְשֵׁם וְגַם־מָצָאתָ חֵן בְּעֵינָי׃
וְעַתָּה אִם־נָא מָצָאתִי חֵן בְּעֵינֶיךָ הוֹדִעֵנִי נָא אֶת־דְּרָכֶךָ וְאֵדָעֲךָ לְמַעַן אֶמְצָא־חֵן בְּעֵינֶיךָ וּרְאֵה כִּי עַמְּךָ הַגּוֹי הַזֶּה׃
וַיֹּאמַר פָּנַי יֵלֵכוּ וַהֲנִחֹתִי לָךְ׃
וַיֹּאמֶר אֵלָיו אִם־אֵין פָּנֶיךָ הֹלְכִים אַל־תַּעֲלֵנוּ מִזֶּה׃
וּבַמֶּה יִוָּדַע אֵפוֹא כִּי־מָצָאתִי חֵן בְּעֵינֶיךָ אֲנִי וְעַמֶּךָ הֲלוֹא בְּלֶכְתְּךָ עִמָּנוּ וְנִפְלֵינוּ אֲנִי וְעַמְּךָ מִכָּל־הָעָם אֲשֶׁר עַל־פְּנֵי הָאֲדָמָה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה גַּם אֶת־הַדָּבָר הַזֶּה אֲשֶׁר דִּבַּרְתָּ אֶעֱשֶׂה כִּי־מָצָאתָ חֵן בְּעֵינַי וָאֵדָעֲךָ בְּשֵׁם׃
וַיֹּאמַר הַרְאֵנִי נָא אֶת־כְּבֹדֶךָ׃
וַיֹּאמֶר אֲנִי אַעֲבִיר כָּל־טוּבִי עַל־פָּנֶיךָ וְקָרָאתִי בְשֵׁם יְהוָה לְפָנֶיךָ וְחַנֹּתִי אֶת־אֲשֶׁר אָחֹן וְרִחַמְתִּי אֶת־אֲשֶׁר אֲרַחֵם׃
וַיֹּאמֶר לֹא תוּכַל לִרְאֹת אֶת־פָּנָי כִּי לֹא־יִרְאַנִי הָאָדָם וָחָי׃
וַיֹּאמֶר יְהוָה הִנֵּה מָקוֹם אִתִּי וְנִצַּבְתָּ עַל־הַצּוּר׃
וְהָיָה בַּעֲבֹר כְּבֹדִי וְשַׂמְתִּיךָ בְּנִקְרַת הַצּוּר וְשַׂכֹּתִי כַפִּי עָלֶיךָ עַד־עָבְרִי׃
וַהֲסִרֹתִי אֶת־כַּפִּי וְרָאִיתָ אֶת־אֲחֹרָי וּפָנַי לֹא יֵרָאוּ׃

Chapter 34

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה פְּסָל־לְךָ שְׁנֵי־לֻחֹת אֲבָנִים כָּרִאשֹׁנִים וְכָתַבְתִּי עַל־הַלֻּחֹת אֶת־הַדְּבָרִים אֲשֶׁר הָיוּ עַל־הַלֻּחֹת הָרִאשֹׁנִים אֲשֶׁר שִׁבַּרְתָּ׃
וֶהְיֵה נָכוֹן לַבֹּקֶר וְעָלִיתָ בַבֹּקֶר אֶל־הַר סִינַי וְנִצַּבְתָּ לִי שָׁם עַל־רֹאשׁ הָהָר׃
וְאִישׁ לֹא־יַעֲלֶה עִמָּךְ וְגַם־אִישׁ אַל־יֵרָא בְּכָל־הָהָר גַּם־הַצֹּאן וְהַבָּקָר אַל־יִרְעוּ אֶל־מוּל הָהָר הַהוּא׃
וַיִּפְסֹל שְׁנֵי־לֻחֹת אֲבָנִים כָּרִאשֹׁנִים וַיַּשְׁכֵּם מֹשֶׁה בַבֹּקֶר וַיַּעַל אֶל־הַר סִינַי כַּאֲשֶׁר צִוָּה יְהוָה אֹתוֹ וַיִּקַּח בְּיָדוֹ שְׁנֵי לֻחֹת אֲבָנִים׃
וַיֵּרֶד יְהוָה בֶּעָנָן וַיִּתְיַצֵּב עִמּוֹ שָׁם וַיִּקְרָא בְשֵׁם יְהוָה׃
וַיַּעֲבֹר יְהוָה עַל־פָּנָיו וַיִּקְרָא יְהוָה יְהוָה אֵל רַחוּם וְחַנּוּן אֶרֶךְ אַפַּיִם וְרַב־חֶסֶד וֶאֱמֶת
נֹצֵר חֶסֶד לָאֲלָפִים נֹשֵׂא עָוֺן וָפֶשַׁע וְחַטָּאָה וְנַקֵּה לֹא יְנַקֶּה פֹּקֵד עֲוֺן אָבוֹת עַל־בָּנִים וְעַל־בְּנֵי בָנִים עַל־שִׁלֵּשִׁים וְעַל־רִבֵּעִים׃
וַיְמַהֵר מֹשֶׁה וַיִּקֹּד אַרְצָה וַיִּשְׁתָּחוּ׃
וַיֹּאמֶר אִם־נָא מָצָאתִי חֵן בְּעֵינֶיךָ אֲדֹנָי יֵלֶךְ־נָא אֲדֹנָי בְּקִרְבֵּנוּ כִּי עַם־קְשֵׁה־עֹרֶף הוּא וְסָלַחְתָּ לַעֲוֺנֵנוּ וּלְחַטָּאתֵנוּ וּנְחַלְתָּנוּ׃
וַיֹּאמֶר הִנֵּה אָנֹכִי כֹּרֵת בְּרִית נֶגֶד כָּל־עַמְּךָ אֶעֱשֶׂה נִפְלָאֹת אֲשֶׁר לֹא־נִבְרְאוּ בְכָל־הָאָרֶץ וּבְכָל־הַגּוֹיִם וְרָאָה כָל־הָעָם אֲשֶׁר־אַתָּה בְקִרְבּוֹ אֶת־מַעֲשֵׂה יְהוָה כִּי־נוֹרָא הוּא אֲשֶׁר אֲנִי עֹשֶׂה עִמָּךְ׃
שְׁמָר־לְךָ אֵת אֲשֶׁר אָנֹכִי מְצַוְּךָ הַיּוֹם הִנְנִי גֹרֵשׁ מִפָּנֶיךָ אֶת־הָאֱמֹרִי וְהַכְּנַעֲנִי וְהַחִתִּי וְהַפְּרִזִּי וְהַחִוִּי וְהַיְבוּסִי׃
הִשָּׁמֶר לְךָ פֶּן־תִּכְרֹת בְּרִית לְיוֹשֵׁב הָאָרֶץ אֲשֶׁר אַתָּה בָּא עָלֶיהָ פֶּן־יִהְיֶה לְמוֹקֵשׁ בְּקִרְבֶּךָ׃
כִּי אֶת־מִזְבְּחֹתָם תִּתֹּצוּן וְאֶת־מַצֵּבֹתָם תְּשַׁבֵּרוּן וְאֶת־אֲשֵׁרָיו תִּכְרֹתוּן׃
כִּי לֹא תִשְׁתַּחֲוֶה לְאֵל אַחֵר כִּי יְהוָה קַנָּא שְׁמוֹ אֵל קַנָּא הוּא׃
פֶּן־תִּכְרֹת בְּרִית לְיוֹשֵׁב הָאָרֶץ וְזָנוּ אַחֲרֵי אֱלֹהֵיהֶם וְזָבְחוּ לֵאלֹהֵיהֶם וְקָרָא לְךָ וְאָכַלְתָּ מִזִּבְחוֹ׃
וְלָקַחְתָּ מִבְּנֹתָיו לְבָנֶיךָ וְזָנוּ בְנֹתָיו אַחֲרֵי אֱלֹהֵיהֶן וְהִזְנוּ אֶת־בָּנֶיךָ אַחֲרֵי אֱלֹהֵיהֶן׃
אֱלֹהֵי מַסֵּכָה לֹא תַעֲשֶׂה־לָּךְ׃
אֶת־חַג הַמַּצּוֹת תִּשְׁמֹר שִׁבְעַת יָמִים תֹּאכַל מַצּוֹת אֲשֶׁר צִוִּיתִךָ לְמוֹעֵד חֹדֶשׁ הָאָבִיב כִּי בְּחֹדֶשׁ הָאָבִיב יָצָאתָ מִמִּצְרָיִם׃
כָּל־פֶּטֶר רֶחֶם לִי וְכָל־מִקְנְךָ תִּזָּכָר פֶּטֶר שׁוֹר וָשֶׂה׃
וּפֶטֶר חֲמוֹר תִּפְדֶּה בְשֶׂה וְאִם־לֹא תִפְדֶּה וַעֲרַפְתּוֹ כֹּל בְּכוֹר בָּנֶיךָ תִּפְדֶּה וְלֹא־יֵרָאוּ פָנַי רֵיקָם׃
שֵׁשֶׁת יָמִים תַּעֲבֹד וּבַיּוֹם הַשְּׁבִיעִי תִּשְׁבֹּת בֶּחָרִישׁ וּבַקָּצִיר תִּשְׁבֹּת׃
וְחַג שָׁבֻעֹת תַּעֲשֶׂה לְךָ בִּכּוּרֵי קְצִיר חִטִּים וְחַג הָאָסִיף תְּקוּפַת הַשָּׁנָה׃
שָׁלֹשׁ פְּעָמִים בַּשָּׁנָה יֵרָאֶה כָּל־זְכוּרְךָ אֶת־פְּנֵי הָאָדֹן יְהוָה אֱלֹהֵי יִשְׂרָאֵל׃
כִּי־אוֹרִישׁ גּוֹיִם מִפָּנֶיךָ וְהִרְחַבְתִּי אֶת־גְּבוּלֶךָ וְלֹא־יַחְמֹד אִישׁ אֶת־אַרְצְךָ בַּעֲלֹתְךָ לֵרָאוֹת אֶת־פְּנֵי יְהוָה אֱלֹהֶיךָ שָׁלֹשׁ פְּעָמִים בַּשָּׁנָה׃
לֹא־תִשְׁחַט עַל־חָמֵץ דַּם־זִבְחִי וְלֹא־יָלִין לַבֹּקֶר זֶבַח חַג הַפָּסַח׃
רֵאשִׁית בִּכּוּרֵי אַדְמָתְךָ תָּבִיא בֵּית יְהוָה אֱלֹהֶיךָ לֹא־תְבַשֵּׁל גְּדִי בַּחֲלֵב אִמּוֹ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה כְּתָב־לְךָ אֶת־הַדְּבָרִים הָאֵלֶּה כִּי עַל־פִּי הַדְּבָרִים הָאֵלֶּה כָּרַתִּי אִתְּךָ בְּרִית וְאֶת־יִשְׂרָאֵל׃
וַיְהִי־שָׁם עִם־יְהוָה אַרְבָּעִים יוֹם וְאַרְבָּעִים לַיְלָה לֶחֶם לֹא אָכַל וּמַיִם לֹא שָׁתָה וַיִּכְתֹּב עַל־הַלֻּחֹת אֵת דִּבְרֵי הַבְּרִית עֲשֶׂרֶת הַדְּבָרִים׃
וַיְהִי בְּרֶדֶת מֹשֶׁה מֵהַר סִינַי וּשְׁנֵי לֻחֹת הָעֵדֻת בְּיַד־מֹשֶׁה בְּרִדְתּוֹ מִן־הָהָר וּמֹשֶׁה לֹא־יָדַע כִּי קָרַן עוֹר פָּנָיו בְּדַבְּרוֹ אִתּוֹ׃
וַיַּרְא אַהֲרֹן וְכָל־בְּנֵי יִשְׂרָאֵל אֶת־מֹשֶׁה וְהִנֵּה קָרַן עוֹר פָּנָיו וַיִּירְאוּ מִגֶּשֶׁת אֵלָיו׃
וַיִּקְרָא אֲלֵהֶם מֹשֶׁה וַיָּשֻׁבוּ אֵלָיו אַהֲרֹן וְכָל־הַנְּשִׂאִים בָּעֵדָה וַיְדַבֵּר מֹשֶׁה אֲלֵהֶם׃
וְאַחֲרֵי־כֵן נִגְּשׁוּ כָּל־בְּנֵי יִשְׂרָאֵל וַיְצַוֵּם אֵת כָּל־אֲשֶׁר דִּבֶּר יְהוָה אִתּוֹ בְּהַר סִינָי׃
וַיְכַל מֹשֶׁה מִדַּבֵּר אִתָּם וַיִּתֵּן עַל־פָּנָיו מַסְוֶה׃
וּבְבֹא מֹשֶׁה לִפְנֵי יְהוָה לְדַבֵּר אִתּוֹ יָסִיר אֶת־הַמַּסְוֶה עַד־צֵאתוֹ וְיָצָא וְדִבֶּר אֶל־בְּנֵי יִשְׂרָאֵל אֵת אֲשֶׁר יְצֻוֶּה׃
וְרָאוּ בְנֵי־יִשְׂרָאֵל אֶת־פְּנֵי מֹשֶׁה כִּי קָרַן עוֹר פְּנֵי מֹשֶׁה וְהֵשִׁיב מֹשֶׁה אֶת־הַמַּסְוֶה עַל־פָּנָיו עַד־בֹּאוֹ לְדַבֵּר אִתּוֹ׃

Chapter 35

וַיַּקְהֵל מֹשֶׁה אֶת־כָּל־עֲדַת בְּנֵי יִשְׂרָאֵל וַיֹּאמֶר אֲלֵהֶם אֵלֶּה הַדְּבָרִים אֲשֶׁר־צִוָּה יְהוָה לַעֲשֹׂת אֹתָם׃
שֵׁשֶׁת יָמִים תֵּעָשֶׂה מְלָאכָה וּבַיּוֹם הַשְּׁבִיעִי יִהְיֶה לָכֶם קֹדֶשׁ שַׁבַּת שַׁבָּתוֹן לַיהוָה כָּל־הָעֹשֶׂה בוֹ מְלָאכָה יוּמָת׃
לֹא־תְבַעֲרוּ אֵשׁ בְּכֹל מֹשְׁבֹתֵיכֶם בְּיוֹם הַשַּׁבָּת׃
וַיֹּאמֶר מֹשֶׁה אֶל־כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל לֵאמֹר זֶה הַדָּבָר אֲשֶׁר־צִוָּה יְהוָה לֵאמֹר׃
קְחוּ מֵאִתְּכֶם תְּרוּמָה לַיהוָה כֹּל נְדִיב לִבּוֹ יְבִיאֶהָ אֵת תְּרוּמַת יְהוָה זָהָב וָכֶסֶף וּנְחֹשֶׁת׃
וּתְכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ וְעִזִּים׃
וְעֹרֹת אֵילִם מְאָדָּמִים וְעֹרֹת תְּחָשִׁים וַעֲצֵי שִׂטִּים׃
וְשֶׁמֶן לַמָּאוֹר וּבְשָׂמִים לְשֶׁמֶן הַמִּשְׁחָה וְלִקְטֹרֶת הַסַּמִּים׃
וְאַבְנֵי־שֹׁהַם וְאַבְנֵי מִלֻּאִים לָאֵפוֹד וְלַחֹשֶׁן׃
וְכָל־חֲכַם־לֵב בָּכֶם יָבֹאוּ וְיַעֲשׂוּ אֵת כָּל־אֲשֶׁר צִוָּה יְהוָה׃
אֶת־הַמִּשְׁכָּן אֶת־אָהֳלוֹ וְאֶת־מִכְסֵהוּ אֶת־קְרָסָיו וְאֶת־קְרָשָׁיו אֶת־בְּרִיחָו אֶת־עַמֻּדָיו וְאֶת־אֲדָנָיו׃
אֶת־הָאָרֹן וְאֶת־בַּדָּיו אֶת־הַכַּפֹּרֶת וְאֵת פָּרֹכֶת הַמָּסָךְ׃
אֶת־הַשֻּׁלְחָן וְאֶת־בַּדָּיו וְאֶת־כָּל־כֵּלָיו וְאֵת לֶחֶם הַפָּנִים׃
וְאֶת־מְנֹרַת הַמָּאוֹר וְאֶת־כֵּלֶיהָ וְאֶת־נֵרֹתֶיהָ וְאֵת שֶׁמֶן הַמָּאוֹר׃
וְאֶת־מִזְבַּח הַקְּטֹרֶת וְאֶת־בַּדָּיו וְאֵת שֶׁמֶן הַמִּשְׁחָה וְאֵת קְטֹרֶת הַסַּמִּים וְאֶת־מָסַךְ הַפֶּתַח לְפֶתַח הַמִּשְׁכָּן׃
אֵת מִזְבַּח הָעֹלָה וְאֶת־מִכְבַּר הַנְּחֹשֶׁת אֲשֶׁר־לוֹ אֶת־בַּדָּיו וְאֶת־כָּל־כֵּלָיו אֶת־הַכִּיֹּר וְאֶת־כַּנּוֹ׃
אֵת קַלְעֵי הֶחָצֵר אֶת־עַמֻּדָיו וְאֶת־אֲדָנֶיהָ וְאֵת מָסַךְ שַׁעַר הֶחָצֵר׃
אֶת־יִתְדֹת הַמִּשְׁכָּן וְאֶת־יִתְדֹת הֶחָצֵר וְאֶת־מֵיתְרֵיהֶם׃
אֶת־בִּגְדֵי הַשְּׂרָד לְשָׁרֵת בַּקֹּדֶשׁ אֶת־בִּגְדֵי הַקֹּדֶשׁ לְאַהֲרֹן הַכֹּהֵן וְאֶת־בִּגְדֵי בָנָיו לְכַהֵן׃
וַיֵּצְאוּ כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל מִלִּפְנֵי מֹשֶׁה׃
וַיָּבֹאוּ כָּל־אִישׁ אֲשֶׁר־נְשָׂאוֹ לִבּוֹ וְכֹל אֲשֶׁר נָדְבָה רוּחוֹ אֹתוֹ הֵבִיאוּ אֶת־תְּרוּמַת יְהוָה לִמְלֶאכֶת אֹהֶל מוֹעֵד וּלְכָל־עֲבֹדָתוֹ וּלְבִגְדֵי הַקֹּדֶשׁ׃
וַיָּבֹאוּ הָאֲנָשִׁים עַל־הַנָּשִׁים כֹּל נְדִיב לֵב הֵבִיאוּ חָח וָנֶזֶם וְטַבַּעַת וְכוּמָז כָּל־כְּלִי זָהָב וְכָל־אִישׁ אֲשֶׁר הֵנִיף תְּנוּפַת זָהָב לַיהוָה׃
וְכָל־אִישׁ אֲשֶׁר־נִמְצָא אִתּוֹ תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ וְעִזִּים וְעֹרֹת אֵילִם מְאָדָּמִים וְעֹרֹת תְּחָשִׁים הֵבִיאוּ׃
כָּל־מֵרִים תְּרוּמַת כֶּסֶף וּנְחֹשֶׁת הֵבִיאוּ אֵת תְּרוּמַת יְהוָה וְכֹל אֲשֶׁר נִמְצָא אִתּוֹ עֲצֵי שִׁטִּים לְכָל־מְלֶאכֶת הָעֲבֹדָה הֵבִיאוּ׃
וְכָל־אִשָּׁה חַכְמַת־לֵב בְּיָדֶיהָ טָווּ וַיָּבִיאוּ מַטְוֶה אֶת־הַתְּכֵלֶת וְאֶת־הָאַרְגָּמָן אֶת־תּוֹלַעַת הַשָּׁנִי וְאֶת־הַשֵּׁשׁ׃
וְכָל־הַנָּשִׁים אֲשֶׁר נָשָׂא לִבָּן אֹתָנָה בְּחָכְמָה טָווּ אֶת־הָעִזִּים׃
וְהַנְּשִׂאִם הֵבִיאוּ אֵת אַבְנֵי הַשֹּׁהַם וְאֵת אַבְנֵי הַמִּלֻּאִים לָאֵפוֹד וְלַחֹשֶׁן׃
וְאֶת־הַבֹּשֶׂם וְאֶת־הַשָּׁמֶן לְמָאוֹר וּלְשֶׁמֶן הַמִּשְׁחָה וְלִקְטֹרֶת הַסַּמִּים׃
כָּל־אִישׁ וְאִשָּׁה אֲשֶׁר נָדַב לִבָּם אֹתָם לְהָבִיא לְכָל־הַמְּלָאכָה אֲשֶׁר צִוָּה יְהוָה לַעֲשׂוֹת בְּיַד־מֹשֶׁה הֵבִיאוּ בְנֵי־יִשְׂרָאֵל נְדָבָה לַיהוָה׃
וַיֹּאמֶר מֹשֶׁה אֶל־בְּנֵי יִשְׂרָאֵל רְאוּ קָרָא יְהוָה בְּשֵׁם בְּצַלְאֵל בֶּן־אוּרִי בֶן־חוּר לְמַטֵּה יְהוּדָה׃
וַיְמַלֵּא אֹתוֹ רוּחַ אֱלֹהִים בְּחָכְמָה בִּתְבוּנָה וּבְדַעַת וּבְכָל־מְלָאכָה׃
וְלַחְשֹׁב מַחַשָׁבֹת לַעֲשֹׂת בַּזָּהָב וּבַכֶּסֶף וּבַנְּחֹשֶׁת׃
וּבַחֲרֹשֶׁת אֶבֶן לְמַלֹּאת וּבַחֲרֹשֶׁת עֵץ לַעֲשׂוֹת בְּכָל־מְלֶאכֶת מַחֲשָׁבֶת׃
וּלְהוֹרֹת נָתַן בְּלִבּוֹ הוּא וְאָהֳלִיאָב בֶּן־אֲחִיסָמָךְ לְמַטֵּה־דָן׃
מִלֵּא אֹתָם חָכְמַת־לֵב לַעֲשׂוֹת כָּל־מְלֶאכֶת חָרָשׁ וְחֹשֵׁב וְרֹקֵם בַּתְּכֵלֶת וּבָאַרְגָּמָן בְּתוֹלַעַת הַשָּׁנִי וּבַשֵּׁשׁ וְאֹרֵג עֹשֵׂי כָּל־מְלָאכָה וְחֹשְׁבֵי מַחֲשָׁבֹת׃

Chapter 36

וְעָשָׂה בְצַלְאֵל וְאָהֳלִיאָב וְכֹל אִישׁ חֲכַם־לֵב אֲשֶׁר נָתַן יְהוָה חָכְמָה וּתְבוּנָה בָּהֵמָּה לָדַעַת לַעֲשֹׂת אֶת־כָּל־מְלֶאכֶת עֲבֹדַת הַקֹּדֶשׁ לְכֹל אֲשֶׁר־צִוָּה יְהוָה׃
וַיִּקְרָא מֹשֶׁה אֶל־בְּצַלְאֵל וְאֶל־אָהֳלִיאָב וְאֶל כָּל־אִישׁ חֲכַם־לֵב אֲשֶׁר נָתַן יְהוָה חָכְמָה בְּלִבּוֹ כֹּל אֲשֶׁר נְשָׂאוֹ לִבּוֹ לְקָרְבָה אֶל־הַמְּלָאכָה לַעֲשֹׂת אֹתָהּ׃
וַיִּקְחוּ מִלִּפְנֵי מֹשֶׁה אֵת כָּל־הַתְּרוּמָה אֲשֶׁר הֵבִיאוּ בְּנֵי יִשְׂרָאֵל לִמְלֶאכֶת עֲבֹדַת הַקֹּדֶשׁ לַעֲשֹׂת אֹתָהּ וְהֵם הֵבִיאוּ אֵלָיו עוֹד נְדָבָה בַּבֹּקֶר בַּבֹּקֶר׃
וַיָּבֹאוּ כָּל־הַחֲכָמִים הָעֹשִׂים אֵת כָּל־מְלֶאכֶת הַקֹּדֶשׁ אִישׁ־אִישׁ מִמְּלַאכְתּוֹ אֲשֶׁר־הֵמָּה עֹשִׂים׃
וַיֹּאמְרוּ אֶל־מֹשֶׁה לֵּאמֹר מַרְבִּים הָעָם לְהָבִיא מִדֵּי הָעֲבֹדָה לַמְּלָאכָה אֲשֶׁר־צִוָּה יְהוָה לַעֲשֹׂת אֹתָהּ׃
וַיְצַו מֹשֶׁה וַיַּעֲבִירוּ קוֹל בַּמַּחֲנֶה לֵאמֹר אִישׁ וְאִשָּׁה אַל־יַעֲשׂוּ־עוֹד מְלָאכָה לִתְרוּמַת הַקֹּדֶשׁ וַיִּכָּלֵא הָעָם מֵהָבִיא׃
וְהַמְּלָאכָה הָיְתָה דַיָּם לְכָל־הַמְּלָאכָה לַעֲשׂוֹת אֹתָהּ וְהוֹתֵר׃
וַיַּעֲשׂוּ כָל־חֲכַם־לֵב בְּעֹשֵׂי הַמְּלָאכָה אֶת־הַמִּשְׁכָּן עֶשֶׂר יְרִיעֹת שֵׁשׁ מָשְׁזָר וּתְכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי כְּרֻבִים מַעֲשֵׂה חֹשֵׁב עָשָׂה אֹתָם׃
אֹרֶךְ הַיְרִיעָה הָאַחַת שְׁמֹנֶה וְעֶשְׂרִים בָּאַמָּה וְרֹחַב אַרְבַּע בָּאַמָּה הַיְרִיעָה הָאֶחָת מִדָּה אַחַת לְכָל־הַיְרִיעֹת׃
וַיְחַבֵּר אֶת־חֲמֵשׁ הַיְרִיעֹת אַחַת אֶל־אֶחָת וְחָמֵשׁ יְרִיעֹת חִבַּר אַחַת אֶל־אֶחָת׃
וַיַּעַשׂ לֻלְאֹת תְּכֵלֶת עַל שְׂפַת הַיְרִיעָה הָאֶחָת מִקָּצָה בַּמַּחְבָּרֶת כֵּן עָשָׂה בִּשְׂפַת הַיְרִיעָה הַקִּיצוֹנָה בַּמַּחְבֶּרֶת הַשֵּׁנִית׃
חֲמִשִּׁים לֻלָאֹת עָשָׂה בַּיְרִיעָה הָאֶחָת וַחֲמִשִּׁים לֻלָאֹת עָשָׂה בִּקְצֵה הַיְרִיעָה אֲשֶׁר בַּמַּחְבֶּרֶת הַשֵּׁנִית מַקְבִּילֹת הַלֻּלָאֹת אַחַת אֶל־אֶחָת׃
וַיַּעַשׂ חֲמִשִּׁים קַרְסֵי זָהָב וַיְחַבֵּר אֶת־הַיְרִעֹת אַחַת אֶל־אַחַת בַּקְּרָסִים וַיְהִי הַמִּשְׁכָּן אֶחָד׃
וַיַּעַשׂ יְרִיעֹת עִזִּים לְאֹהֶל עַל־הַמִּשְׁכָּן עַשְׁתֵּי־עֶשְׂרֵה יְרִיעֹת עָשָׂה אֹתָם׃
אֹרֶךְ הַיְרִיעָה הָאַחַת שְׁלֹשִׁים בָּאַמָּה וְאַרְבַּע אַמּוֹת רֹחַב הַיְרִיעָה הָאֶחָת מִדָּה אַחַת לְעַשְׁתֵּי עֶשְׂרֵה יְרִיעֹת׃
וַיְחַבֵּר אֶת־חֲמֵשׁ הַיְרִיעֹת לְבָד וְאֶת־שֵׁשׁ הַיְרִיעֹת לְבָד׃
וַיַּעַשׂ לֻלָאֹת חֲמִשִּׁים עַל שְׂפַת הַיְרִיעָה הַקִּיצֹנָה בַּמַּחְבָּרֶת וַחֲמִשִּׁים לֻלָאֹת עָשָׂה עַל־שְׂפַת הַיְרִיעָה הַחֹבֶרֶת הַשֵּׁנִית׃
וַיַּעַשׂ קַרְסֵי נְחֹשֶׁת חֲמִשִּׁים לְחַבֵּר אֶת־הָאֹהֶל לִהְיֹת אֶחָד׃
וַיַּעַשׂ מִכְסֶה לָאֹהֶל עֹרֹת אֵלִים מְאָדָּמִים וּמִכְסֵה עֹרֹת תְּחָשִׁים מִלְמָעְלָה׃
וַיַּעַשׂ אֶת־הַקְּרָשִׁים לַמִּשְׁכָּן עֲצֵי שִׁטִּים עֹמְדִים׃
עֶשֶׂר אַמֹּת אֹרֶךְ הַקָּרֶשׁ וְאַמָּה וַחֲצִי הָאַמָּה רֹחַב הַקֶּרֶשׁ הָאֶחָד׃
שְׁתֵּי יָדֹת לַקֶּרֶשׁ הָאֶחָד מְשֻׁלָּבֹת אַחַת אֶל־אֶחָת כֵּן עָשָׂה לְכֹל קַרְשֵׁי הַמִּשְׁכָּן׃
וַיַּעַשׂ אֶת־הַקְּרָשִׁים לַמִּשְׁכָּן עֶשְׂרִים קְרָשִׁים לִפְאַת נֶגֶב תֵּימָנָה׃
וְאַרְבָּעִים אַדְנֵי־כֶסֶף עָשָׂה תַּחַת עֶשְׂרִים הַקְּרָשִׁים שְׁנֵי אֲדָנִים תַּחַת־הַקֶּרֶשׁ הָאֶחָד לִשְׁתֵּי יְדֹתָיו וּשְׁנֵי אֲדָנִים תַּחַת־הַקֶּרֶשׁ הָאֶחָד לִשְׁתֵּי יְדֹתָיו׃
וּלְצֶלַע הַמִּשְׁכָּן הַשֵּׁנִית לִפְאַת צָפוֹן עָשָׂה עֶשְׂרִים קְרָשִׁים׃
וְאַרְבָּעִים אַדְנֵיהֶם כָּסֶף שְׁנֵי אֲדָנִים תַּחַת הַקֶּרֶשׁ הָאֶחָד וּשְׁנֵי אֲדָנִים תַּחַת הַקֶּרֶשׁ הָאֶחָד׃
וּלְיַרְכְּתֵי הַמִּשְׁכָּן יָמָּה עָשָׂה שִׁשָּׁה קְרָשִׁים׃
וּשְׁנֵי קְרָשִׁים עָשָׂה לִמְקֻצְעֹת הַמִּשְׁכָּן בַּיַּרְכָתָיִם׃
וְהָיוּ תוֹאֲמִם מִלְּמַטָּה וְיַחְדָּו יִהְיוּ תַמִּים אֶל־רֹאשׁוֹ אֶל־הַטַּבַּעַת הָאֶחָת כֵּן עָשָׂה לִשְׁנֵיהֶם לִשְׁנֵי הַמִּקְצֹעֹת׃
וְהָיוּ שְׁמֹנָה קְרָשִׁים וְאַדְנֵיהֶם כֶּסֶף שִׁשָּׁה עָשָׂר אֲדָנִים שְׁנֵי אֲדָנִים שְׁנֵי אֲדָנִים תַּחַת הַקֶּרֶשׁ הָאֶחָד׃
וַיַּעַשׂ בְּרִיחֵי עֲצֵי שִׁטִּים חֲמִשָּׁה לְקַרְשֵׁי צֶלַע־הַמִּשְׁכָּן הָאֶחָת׃
וַחֲמִשָּׁה בְרִיחִם לְקַרְשֵׁי צֶלַע־הַמִּשְׁכָּן הַשֵּׁנִית וַחֲמִשָּׁה בְרִיחִם לְקַרְשֵׁי הַמִּשְׁכָּן לַיַּרְכָתַיִם יָמָּה׃
וַיַּעַשׂ אֶת־הַבְּרִיחַ הַתִּיכֹן לִבְרֹחַ בְּתוֹךְ הַקְּרָשִׁים מִן־הַקָּצֶה אֶל־הַקָּצֶה׃
וְאֶת־הַקְּרָשִׁים צִפָּה זָהָב וְאֶת־טַבְּעֹתָם עָשָׂה זָהָב בָּתִּים לַבְּרִיחִם וַיְצַף אֶת־הַבְּרִיחִם זָהָב׃
וַיַּעַשׂ אֶת־הַפָּרֹכֶת תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר מַעֲשֵׂה חֹשֵׁב עָשָׂה אֹתָהּ כְּרֻבִים׃
וַיַּעַשׂ לָהּ אַרְבָּעָה עַמּוּדֵי שִׁטִּים וַיְצַפֵּם זָהָב וָוֵיהֶם זָהָב וַיִּצֹק לָהֶם אַרְבָּעָה אַדְנֵי־כָסֶף׃
וַיַּעַשׂ מָסָךְ לְפֶתַח הָאֹהֶל תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר מַעֲשֵׂה רֹקֵם׃
וְאֶת־עַמּוּדָיו חֲמִשָּׁה וְאֶת־וָוֵיהֶם וְצִפָּה רָאשֵׁיהֶם וַחֲשֻׁקֵיהֶם זָהָב וְאַדְנֵיהֶם חֲמִשָּׁה נְחֹשֶׁת׃

Chapter 37

וַיַּעַשׂ בְּצַלְאֵל אֶת־הָאָרֹן עֲצֵי שִׁטִּים אַמָּתַיִם וָחֵצִי אָרְכּוֹ וְאַמָּה וָחֵצִי רָחְבּוֹ וְאַמָּה וָחֵצִי קֹמָתוֹ׃
וַיְצַפֵּהוּ זָהָב טָהוֹר מִבַּיִת וּמִחוּץ וַיַּעַשׂ לוֹ זֵר זָהָב סָבִיב׃
וַיִּצֹק לוֹ אַרְבַּע טַבְּעֹת זָהָב עַל אַרְבַּע פַּעֲמֹתָיו וּשְׁתֵּי טַבָּעֹת עַל־צַלְעוֹ הָאֶחָת וּשְׁתֵּי טַבָּעוֹת עַל־צַלְעוֹ הַשֵּׁנִית׃
וַיַּעַשׂ בַּדֵּי עֲצֵי שִׁטִּים וַיְצַף אֹתָם זָהָב׃
וַיָּבֵא אֶת־הַבַּדִּים בַּטַּבָּעֹת עַל צַלְעֹת הָאָרֹן לָשֵׂאת אֶת־הָאָרֹן׃
וַיַּעַשׂ כַּפֹּרֶת זָהָב טָהוֹר אַמָּתַיִם וָחֵצִי אָרְכָּהּ וְאַמָּה וָחֵצִי רָחְבָּהּ׃
וַיַּעַשׂ שְׁנֵי כְרֻבִים זָהָב מִקְשָׁה עָשָׂה אֹתָם מִשְּׁנֵי קְצוֹת הַכַּפֹּרֶת׃
כְּרוּב־אֶחָד מִקָּצָה מִזֶּה וּכְרוּב־אֶחָד מִקָּצָה מִזֶּה מִן־הַכַּפֹּרֶת עָשָׂה אֶת־הַכְּרֻבִים מִשְּׁנֵי קצוותו [קְצוֹתָיו׃]
וַיִּהְיוּ הַכְּרֻבִים פֹּרְשֵׂי כְנָפַיִם לְמַעְלָה סֹכְכִים בְּכַנְפֵיהֶם עַל־הַכַּפֹּרֶת וּפְנֵיהֶם אִישׁ אֶל־אָחִיו אֶל־הַכַּפֹּרֶת הָיוּ פְּנֵי הַכְּרֻבִים׃
וַיַּעַשׂ אֶת־הַשֻּׁלְחָן עֲצֵי שִׁטִּים אַמָּתַיִם אָרְכּוֹ וְאַמָּה רָחְבּוֹ וְאַמָּה וָחֵצִי קֹמָתוֹ׃
וַיְצַף אֹתוֹ זָהָב טָהוֹר וַיַּעַשׂ לוֹ זֵר זָהָב סָבִיב׃
וַיַּעַשׂ לוֹ מִסְגֶּרֶת טֹפַח סָבִיב וַיַּעַשׂ זֵר־זָהָב לְמִסְגַּרְתּוֹ סָבִיב׃
וַיִּצֹק לוֹ אַרְבַּע טַבְּעֹת זָהָב וַיִּתֵּן אֶת־הַטַּבָּעֹת עַל אַרְבַּע הַפֵּאֹת אֲשֶׁר לְאַרְבַּע רַגְלָיו׃
לְעֻמַּת הַמִּסְגֶּרֶת הָיוּ הַטַּבָּעֹת בָּתִּים לַבַּדִּים לָשֵׂאת אֶת־הַשֻּׁלְחָן׃
וַיַּעַשׂ אֶת־הַבַּדִּים עֲצֵי שִׁטִּים וַיְצַף אֹתָם זָהָב לָשֵׂאת אֶת־הַשֻּׁלְחָן׃
וַיַּעַשׂ אֶת־הַכֵּלִים אֲשֶׁר עַל־הַשֻּׁלְחָן אֶת־קְעָרֹתָיו וְאֶת־כַּפֹּתָיו וְאֵת מְנַקִּיֹּתָיו וְאֶת־הַקְּשָׂוֺת אֲשֶׁר יֻסַּךְ בָּהֵן זָהָב טָהוֹר׃
וַיַּעַשׂ אֶת־הַמְּנֹרָה זָהָב טָהוֹר מִקְשָׁה עָשָׂה אֶת־הַמְּנֹרָה יְרֵכָהּ וְקָנָהּ גְּבִיעֶיהָ כַּפְתֹּרֶיהָ וּפְרָחֶיהָ מִמֶּנָּה הָיוּ׃
וְשִׁשָּׁה קָנִים יֹצְאִים מִצִּדֶּיהָ שְׁלֹשָׁה קְנֵי מְנֹרָה מִצִּדָּהּ הָאֶחָד וּשְׁלֹשָׁה קְנֵי מְנֹרָה מִצִּדָּהּ הַשֵּׁנִי׃
שְׁלֹשָׁה גְבִעִים מְשֻׁקָּדִים בַּקָּנֶה הָאֶחָד כַּפְתֹּר וָפֶרַח וּשְׁלֹשָׁה גְבִעִים מְשֻׁקָּדִים בְּקָנֶה אֶחָד כַּפְתֹּר וָפָרַח כֵּן לְשֵׁשֶׁת הַקָּנִים הַיֹּצְאִים מִן־הַמְּנֹרָה׃
וּבַמְּנֹרָה אַרְבָּעָה גְבִעִים מְשֻׁקָּדִים כַּפְתֹּרֶיהָ וּפְרָחֶיהָ׃
וְכַפְתֹּר תַּחַת שְׁנֵי הַקָּנִים מִמֶּנָּה וְכַפְתֹּר תַּחַת שְׁנֵי הַקָּנִים מִמֶּנָּה וְכַפְתֹּר תַּחַת־שְׁנֵי הַקָּנִים מִמֶּנָּה לְשֵׁשֶׁת הַקָּנִים הַיֹּצְאִים מִמֶּנָּה׃
כַּפְתֹּרֵיהֶם וּקְנֹתָם מִמֶּנָּה הָיוּ כֻּלָּהּ מִקְשָׁה אַחַת זָהָב טָהוֹר׃
וַיַּעַשׂ אֶת־נֵרֹתֶיהָ שִׁבְעָה וּמַלְקָחֶיהָ וּמַחְתֹּתֶיהָ זָהָב טָהוֹר׃
כִּכָּר זָהָב טָהוֹר עָשָׂה אֹתָהּ וְאֵת כָּל־כֵּלֶיהָ׃
וַיַּעַשׂ אֶת־מִזְבַּח הַקְּטֹרֶת עֲצֵי שִׁטִּים אַמָּה אָרְכּוֹ וְאַמָּה רָחְבּוֹ רָבוּעַ וְאַמָּתַיִם קֹמָתוֹ מִמֶּנּוּ הָיוּ קַרְנֹתָיו׃
וַיְצַף אֹתוֹ זָהָב טָהוֹר אֶת־גַּגּוֹ וְאֶת־קִירֹתָיו סָבִיב וְאֶת־קַרְנֹתָיו וַיַּעַשׂ לוֹ זֵר זָהָב סָבִיב׃
וּשְׁתֵּי טַבְּעֹת זָהָב עָשָׂה־לוֹ מִתַּחַת לְזֵרוֹ עַל שְׁתֵּי צַלְעֹתָיו עַל שְׁנֵי צִדָּיו לְבָתִּים לְבַדִּים לָשֵׂאת אֹתוֹ בָּהֶם׃
וַיַּעַשׂ אֶת־הַבַּדִּים עֲצֵי שִׁטִּים וַיְצַף אֹתָם זָהָב׃
וַיַּעַשׂ אֶת־שֶׁמֶן הַמִּשְׁחָה קֹדֶשׁ וְאֶת־קְטֹרֶת הַסַּמִּים טָהוֹר מַעֲשֵׂה רֹקֵחַ׃

Chapter 38

וַיַּעַשׂ אֶת־מִזְבַּח הָעֹלָה עֲצֵי שִׁטִּים חָמֵשׁ אַמּוֹת אָרְכּוֹ וְחָמֵשׁ־אַמּוֹת רָחְבּוֹ רָבוּעַ וְשָׁלֹשׁ אַמּוֹת קֹמָתוֹ׃
וַיַּעַשׂ קַרְנֹתָיו עַל אַרְבַּע פִּנֹּתָיו מִמֶּנּוּ הָיוּ קַרְנֹתָיו וַיְצַף אֹתוֹ נְחֹשֶׁת׃
וַיַּעַשׂ אֶת־כָּל־כְּלֵי הַמִּזְבֵּחַ אֶת־הַסִּירֹת וְאֶת־הַיָּעִים וְאֶת־הַמִּזְרָקֹת אֶת־הַמִּזְלָגֹת וְאֶת־הַמַּחְתֹּת כָּל־כֵּלָיו עָשָׂה נְחֹשֶׁת׃
וַיַּעַשׂ לַמִּזְבֵּחַ מִכְבָּר מַעֲשֵׂה רֶשֶׁת נְחֹשֶׁת תַּחַת כַּרְכֻּבּוֹ מִלְּמַטָּה עַד־חֶצְיוֹ׃
וַיִּצֹק אַרְבַּע טַבָּעֹת בְּאַרְבַּע הַקְּצָוֺת לְמִכְבַּר הַנְּחֹשֶׁת בָּתִּים לַבַּדִּים׃
וַיַּעַשׂ אֶת־הַבַּדִּים עֲצֵי שִׁטִּים וַיְצַף אֹתָם נְחֹשֶׁת׃
וַיָּבֵא אֶת־הַבַּדִּים בַּטַּבָּעֹת עַל צַלְעֹת הַמִּזְבֵּחַ לָשֵׂאת אֹתוֹ בָּהֶם נְבוּב לֻחֹת עָשָׂה אֹתוֹ׃
וַיַּעַשׂ אֵת הַכִּיּוֹר נְחֹשֶׁת וְאֵת כַּנּוֹ נְחֹשֶׁת בְּמַרְאֹת הַצֹּבְאֹת אֲשֶׁר צָבְאוּ פֶּתַח אֹהֶל מוֹעֵד׃
וַיַּעַשׂ אֶת־הֶחָצֵר לִפְאַת נֶגֶב תֵּימָנָה קַלְעֵי הֶחָצֵר שֵׁשׁ מָשְׁזָר מֵאָה בָּאַמָּה׃
עַמּוּדֵיהֶם עֶשְׂרִים וְאַדְנֵיהֶם עֶשְׂרִים נְחֹשֶׁת וָוֵי הָעַמֻּדִים וַחֲשֻׁקֵיהֶם כָּסֶף׃
וְלִפְאַת צָפוֹן מֵאָה בָאַמָּה עַמּוּדֵיהֶם עֶשְׂרִים וְאַדְנֵיהֶם עֶשְׂרִים נְחֹשֶׁת וָוֵי הָעַמּוּדִים וַחֲשֻׁקֵיהֶם כָּסֶף׃
וְלִפְאַת־יָם קְלָעִים חֲמִשִּׁים בָּאַמָּה עַמּוּדֵיהֶם עֲשָׂרָה וְאַדְנֵיהֶם עֲשָׂרָה וָוֵי הָעַמֻּדִים וַחֲשׁוּקֵיהֶם כָּסֶף׃
וְלִפְאַת קֵדְמָה מִזְרָחָה חֲמִשִּׁים אַמָּה׃
קְלָעִים חֲמֵשׁ־עֶשְׂרֵה אַמָּה אֶל־הַכָּתֵף עַמּוּדֵיהֶם שְׁלֹשָׁה וְאַדְנֵיהֶם שְׁלֹשָׁה׃
וְלַכָּתֵף הַשֵּׁנִית מִזֶּה וּמִזֶּה לְשַׁעַר הֶחָצֵר קְלָעִים חֲמֵשׁ עֶשְׂרֵה אַמָּה עַמֻּדֵיהֶם שְׁלֹשָׁה וְאַדְנֵיהֶם שְׁלֹשָׁה׃
כָּל־קַלְעֵי הֶחָצֵר סָבִיב שֵׁשׁ מָשְׁזָר׃
וְהָאֲדָנִים לָעַמֻּדִים נְחֹשֶׁת וָוֵי הָעַמּוּדִים וַחֲשׁוּקֵיהֶם כֶּסֶף וְצִפּוּי רָאשֵׁיהֶם כָּסֶף וְהֵם מְחֻשָּׁקִים כֶּסֶף כֹּל עַמֻּדֵי הֶחָצֵר׃
וּמָסַךְ שַׁעַר הֶחָצֵר מַעֲשֵׂה רֹקֵם תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר וְעֶשְׂרִים אַמָּה אֹרֶךְ וְקוֹמָה בְרֹחַב חָמֵשׁ אַמּוֹת לְעֻמַּת קַלְעֵי הֶחָצֵר׃
וְעַמֻּדֵיהֶם אַרְבָּעָה וְאַדְנֵיהֶם אַרְבָּעָה נְחֹשֶׁת וָוֵיהֶם כֶּסֶף וְצִפּוּי רָאשֵׁיהֶם וַחֲשֻׁקֵיהֶם כָּסֶף׃
וְכָל־הַיְתֵדֹת לַמִּשְׁכָּן וְלֶחָצֵר סָבִיב נְחֹשֶׁת׃
אֵלֶּה פְקוּדֵי הַמִּשְׁכָּן מִשְׁכַּן הָעֵדֻת אֲשֶׁר פֻּקַּד עַל־פִּי מֹשֶׁה עֲבֹדַת הַלְוִיִּם בְּיַד אִיתָמָר בֶּן־אַהֲרֹן הַכֹּהֵן׃
וּבְצַלְאֵל בֶּן־אוּרִי בֶן־חוּר לְמַטֵּה יְהוּדָה עָשָׂה אֵת כָּל־אֲשֶׁר־צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וְאִתּוֹ אָהֳלִיאָב בֶּן־אֲחִיסָמָךְ לְמַטֵּה־דָן חָרָשׁ וְחֹשֵׁב וְרֹקֵם בַּתְּכֵלֶת וּבָאַרְגָּמָן וּבְתוֹלַעַת הַשָּׁנִי וּבַשֵּׁשׁ׃
כָּל־הַזָּהָב הֶעָשׂוּי לַמְּלָאכָה בְּכֹל מְלֶאכֶת הַקֹּדֶשׁ וַיְהִי זְהַב הַתְּנוּפָה תֵּשַׁע וְעֶשְׂרִים כִּכָּר וּשְׁבַע מֵאוֹת וּשְׁלֹשִׁים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ׃
וְכֶסֶף פְּקוּדֵי הָעֵדָה מְאַת כִּכָּר וְאֶלֶף וּשְׁבַע מֵאוֹת וַחֲמִשָּׁה וְשִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ׃
בֶּקַע לַגֻּלְגֹּלֶת מַחֲצִית הַשֶּׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ לְכֹל הָעֹבֵר עַל־הַפְּקֻדִים מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה לְשֵׁשׁ־מֵאוֹת אֶלֶף וּשְׁלֹשֶׁת אֲלָפִים וַחֲמֵשׁ מֵאוֹת וַחֲמִשִּׁים׃
וַיְהִי מְאַת כִּכַּר הַכֶּסֶף לָצֶקֶת אֵת אַדְנֵי הַקֹּדֶשׁ וְאֵת אַדְנֵי הַפָּרֹכֶת מְאַת אֲדָנִים לִמְאַת הַכִּכָּר כִּכָּר לָאָדֶן׃
וְאֶת־הָאֶלֶף וּשְׁבַע הַמֵּאוֹת וַחֲמִשָּׁה וְשִׁבְעִים עָשָׂה וָוִים לָעַמּוּדִים וְצִפָּה רָאשֵׁיהֶם וְחִשַּׁק אֹתָם׃
וּנְחֹשֶׁת הַתְּנוּפָה שִׁבְעִים כִּכָּר וְאַלְפַּיִם וְאַרְבַּע־מֵאוֹת שָׁקֶל׃
וַיַּעַשׂ בָּהּ אֶת־אַדְנֵי פֶּתַח אֹהֶל מוֹעֵד וְאֵת מִזְבַּח הַנְּחֹשֶׁת וְאֶת־מִכְבַּר הַנְּחֹשֶׁת אֲשֶׁר־לוֹ וְאֵת כָּל־כְּלֵי הַמִּזְבֵּחַ׃
וְאֶת־אַדְנֵי הֶחָצֵר סָבִיב וְאֶת־אַדְנֵי שַׁעַר הֶחָצֵר וְאֵת כָּל־יִתְדֹת הַמִּשְׁכָּן וְאֶת־כָּל־יִתְדֹת הֶחָצֵר סָבִיב׃

Chapter 39

וּמִן־הַתְּכֵלֶת וְהָאַרְגָּמָן וְתוֹלַעַת הַשָּׁנִי עָשׂוּ בִגְדֵי־שְׂרָד לְשָׁרֵת בַּקֹּדֶשׁ וַיַּעֲשׂוּ אֶת־בִּגְדֵי הַקֹּדֶשׁ אֲשֶׁר לְאַהֲרֹן כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּעַשׂ אֶת־הָאֵפֹד זָהָב תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר׃
וַיְרַקְּעוּ אֶת־פַּחֵי הַזָּהָב וְקִצֵּץ פְּתִילִם לַעֲשׂוֹת בְּתוֹךְ הַתְּכֵלֶת וּבְתוֹךְ הָאַרְגָּמָן וּבְתוֹךְ תּוֹלַעַת הַשָּׁנִי וּבְתוֹךְ הַשֵּׁשׁ מַעֲשֵׂה חֹשֵׁב׃
כְּתֵפֹת עָשׂוּ־לוֹ חֹבְרֹת עַל־שְׁנֵי קצוותו [קְצוֹתָיו] חֻבָּר׃
וְחֵשֶׁב אֲפֻדָּתוֹ אֲשֶׁר עָלָיו מִמֶּנּוּ הוּא כְּמַעֲשֵׂהוּ זָהָב תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּעֲשׂוּ אֶת־אַבְנֵי הַשֹּׁהַם מֻסַבֹּת מִשְׁבְּצֹת זָהָב מְפֻתָּחֹת פִּתּוּחֵי חוֹתָם עַל־שְׁמוֹת בְּנֵי יִשְׂרָאֵל׃
וַיָּשֶׂם אֹתָם עַל כִּתְפֹת הָאֵפֹד אַבְנֵי זִכָּרוֹן לִבְנֵי יִשְׂרָאֵל כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּעַשׂ אֶת־הַחֹשֶׁן מַעֲשֵׂה חֹשֵׁב כְּמַעֲשֵׂה אֵפֹד זָהָב תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי וְשֵׁשׁ מָשְׁזָר׃
רָבוּעַ הָיָה כָּפוּל עָשׂוּ אֶת־הַחֹשֶׁן זֶרֶת אָרְכּוֹ וְזֶרֶת רָחְבּוֹ כָּפוּל׃
וַיְמַלְאוּ־בוֹ אַרְבָּעָה טוּרֵי אָבֶן טוּר אֹדֶם פִּטְדָה וּבָרֶקֶת הַטּוּר הָאֶחָד׃
וְהַטּוּר הַשֵּׁנִי נֹפֶךְ סַפִּיר וְיָהֲלֹם׃
וְהַטּוּר הַשְּׁלִישִׁי לֶשֶׁם שְׁבוֹ וְאַחְלָמָה׃
וְהַטּוּר הָרְבִיעִי תַּרְשִׁישׁ שֹׁהַם וְיָשְׁפֵה מוּסַבֹּת מִשְׁבְּצוֹת זָהָב בְּמִלֻּאֹתָם׃
וְהָאֲבָנִים עַל־שְׁמֹת בְּנֵי־יִשְׂרָאֵל הֵנָּה שְׁתֵּים עֶשְׂרֵה עַל־שְׁמֹתָם פִּתּוּחֵי חֹתָם אִישׁ עַל־שְׁמוֹ לִשְׁנֵים עָשָׂר שָׁבֶט׃
וַיַּעֲשׂוּ עַל־הַחֹשֶׁן שַׁרְשְׁרֹת גַּבְלֻת מַעֲשֵׂה עֲבֹת זָהָב טָהוֹר׃
וַיַּעֲשׂוּ שְׁתֵּי מִשְׁבְּצֹת זָהָב וּשְׁתֵּי טַבְּעֹת זָהָב וַיִּתְּנוּ אֶת־שְׁתֵּי הַטַּבָּעֹת עַל־שְׁנֵי קְצוֹת הַחֹשֶׁן׃
וַיִּתְּנוּ שְׁתֵּי הָעֲבֹתֹת הַזָּהָב עַל־שְׁתֵּי הַטַּבָּעֹת עַל־קְצוֹת הַחֹשֶׁן׃
וְאֵת שְׁתֵּי קְצוֹת שְׁתֵּי הָעֲבֹתֹת נָתְנוּ עַל־שְׁתֵּי הַמִּשְׁבְּצֹת וַיִּתְּנֻם עַל־כִּתְפֹת הָאֵפֹד אֶל־מוּל פָּנָיו׃
וַיַּעֲשׂוּ שְׁתֵּי טַבְּעֹת זָהָב וַיָּשִׂימוּ עַל־שְׁנֵי קְצוֹת הַחֹשֶׁן עַל־שְׂפָתוֹ אֲשֶׁר אֶל־עֵבֶר הָאֵפֹד בָּיְתָה׃
וַיַּעֲשׂוּ שְׁתֵּי טַבְּעֹת זָהָב וַיִּתְּנֻם עַל־שְׁתֵּי כִתְפֹת הָאֵפֹד מִלְמַטָּה מִמּוּל פָּנָיו לְעֻמַּת מֶחְבַּרְתּוֹ מִמַּעַל לְחֵשֶׁב הָאֵפֹד׃
וַיִּרְכְּסוּ אֶת־הַחֹשֶׁן מִטַּבְּעֹתָיו אֶל־טַבְּעֹת הָאֵפֹד בִּפְתִיל תְּכֵלֶת לִהְיֹת עַל־חֵשֶׁב הָאֵפֹד וְלֹא־יִזַּח הַחֹשֶׁן מֵעַל הָאֵפֹד כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּעַשׂ אֶת־מְעִיל הָאֵפֹד מַעֲשֵׂה אֹרֵג כְּלִיל תְּכֵלֶת׃
וּפִי־הַמְּעִיל בְּתוֹכוֹ כְּפִי תַחְרָא שָׂפָה לְפִיו סָבִיב לֹא יִקָּרֵעַ׃
וַיַּעֲשׂוּ עַל־שׁוּלֵי הַמְּעִיל רִמּוֹנֵי תְּכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי מָשְׁזָר׃
וַיַּעֲשׂוּ פַעֲמֹנֵי זָהָב טָהוֹר וַיִּתְּנוּ אֶת־הַפַּעֲמֹנִים בְּתוֹךְ הָרִמֹּנִים עַל־שׁוּלֵי הַמְּעִיל סָבִיב בְּתוֹךְ הָרִמֹּנִים׃
פַּעֲמֹן וְרִמֹּן פַּעֲמֹן וְרִמֹּן עַל־שׁוּלֵי הַמְּעִיל סָבִיב לְשָׁרֵת כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּעֲשׂוּ אֶת־הַכָּתְנֹת שֵׁשׁ מַעֲשֵׂה אֹרֵג לְאַהֲרֹן וּלְבָנָיו׃
וְאֵת הַמִּצְנֶפֶת שֵׁשׁ וְאֶת־פַּאֲרֵי הַמִּגְבָּעֹת שֵׁשׁ וְאֶת־מִכְנְסֵי הַבָּד שֵׁשׁ מָשְׁזָר׃
וְאֶת־הָאַבְנֵט שֵׁשׁ מָשְׁזָר וּתְכֵלֶת וְאַרְגָּמָן וְתוֹלַעַת שָׁנִי מַעֲשֵׂה רֹקֵם כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּעֲשׂוּ אֶת־צִיץ נֵזֶר־הַקֹּדֶשׁ זָהָב טָהוֹר וַיִּכְתְּבוּ עָלָיו מִכְתַּב פִּתּוּחֵי חוֹתָם קֹדֶשׁ לַיהוָה׃
וַיִּתְּנוּ עָלָיו פְּתִיל תְּכֵלֶת לָתֵת עַל־הַמִּצְנֶפֶת מִלְמָעְלָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַתֵּכֶל כָּל־עֲבֹדַת מִשְׁכַּן אֹהֶל מוֹעֵד וַיַּעֲשׂוּ בְּנֵי יִשְׂרָאֵל כְּכֹל אֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה כֵּן עָשׂוּ׃
וַיָּבִיאוּ אֶת־הַמִּשְׁכָּן אֶל־מֹשֶׁה אֶת־הָאֹהֶל וְאֶת־כָּל־כֵּלָיו קְרָסָיו קְרָשָׁיו בריחו [בְּרִיחָיו] וְעַמֻּדָיו וַאֲדָנָיו׃
וְאֶת־מִכְסֵה עוֹרֹת הָאֵילִם הַמְאָדָּמִים וְאֶת־מִכְסֵה עֹרֹת הַתְּחָשִׁים וְאֵת פָּרֹכֶת הַמָּסָךְ׃
אֶת־אֲרֹן הָעֵדֻת וְאֶת־בַּדָּיו וְאֵת הַכַּפֹּרֶת׃
אֶת־הַשֻּׁלְחָן אֶת־כָּל־כֵּלָיו וְאֵת לֶחֶם הַפָּנִים׃
אֶת־הַמְּנֹרָה הַטְּהֹרָה אֶת־נֵרֹתֶיהָ נֵרֹת הַמַּעֲרָכָה וְאֶת־כָּל־כֵּלֶיהָ וְאֵת שֶׁמֶן הַמָּאוֹר׃
וְאֵת מִזְבַּח הַזָּהָב וְאֵת שֶׁמֶן הַמִּשְׁחָה וְאֵת קְטֹרֶת הַסַּמִּים וְאֵת מָסַךְ פֶּתַח הָאֹהֶל׃
אֵת מִזְבַּח הַנְּחֹשֶׁת וְאֶת־מִכְבַּר הַנְּחֹשֶׁת אֲשֶׁר־לוֹ אֶת־בַּדָּיו וְאֶת־כָּל־כֵּלָיו אֶת־הַכִּיֹּר וְאֶת־כַּנּוֹ׃
אֵת קַלְעֵי הֶחָצֵר אֶת־עַמֻּדֶיהָ וְאֶת־אֲדָנֶיהָ וְאֶת־הַמָּסָךְ לְשַׁעַר הֶחָצֵר אֶת־מֵיתָרָיו וִיתֵדֹתֶיהָ וְאֵת כָּל־כְּלֵי עֲבֹדַת הַמִּשְׁכָּן לְאֹהֶל מוֹעֵד׃
אֶת־בִּגְדֵי הַשְּׂרָד לְשָׁרֵת בַּקֹּדֶשׁ אֶת־בִּגְדֵי הַקֹּדֶשׁ לְאַהֲרֹן הַכֹּהֵן וְאֶת־בִּגְדֵי בָנָיו לְכַהֵן׃
כְּכֹל אֲשֶׁר־צִוָּה יְהוָה אֶת־מֹשֶׁה כֵּן עָשׂוּ בְּנֵי יִשְׂרָאֵל אֵת כָּל־הָעֲבֹדָה׃
וַיַּרְא מֹשֶׁה אֶת־כָּל־הַמְּלָאכָה וְהִנֵּה עָשׂוּ אֹתָהּ כַּאֲשֶׁר צִוָּה יְהוָה כֵּן עָשׂוּ וַיְבָרֶךְ אֹתָם מֹשֶׁה׃

Chapter 40

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
בְּיוֹם־הַחֹדֶשׁ הָרִאשׁוֹן בְּאֶחָד לַחֹדֶשׁ תָּקִים אֶת־מִשְׁכַּן אֹהֶל מוֹעֵד׃
וְשַׂמְתָּ שָׁם אֵת אֲרוֹן הָעֵדוּת וְסַכֹּתָ עַל־הָאָרֹן אֶת־הַפָּרֹכֶת׃
וְהֵבֵאתָ אֶת־הַשֻּׁלְחָן וְעָרַכְתָּ אֶת־עֶרְכּוֹ וְהֵבֵאתָ אֶת־הַמְּנֹרָה וְהַעֲלֵיתָ אֶת־נֵרֹתֶיהָ׃
וְנָתַתָּה אֶת־מִזְבַּח הַזָּהָב לִקְטֹרֶת לִפְנֵי אֲרוֹן הָעֵדֻת וְשַׂמְתָּ אֶת־מָסַךְ הַפֶּתַח לַמִּשְׁכָּן׃
וְנָתַתָּה אֵת מִזְבַּח הָעֹלָה לִפְנֵי פֶּתַח מִשְׁכַּן אֹהֶל־מוֹעֵד׃
וְנָתַתָּ אֶת־הַכִּיֹּר בֵּין־אֹהֶל מוֹעֵד וּבֵין הַמִּזְבֵּחַ וְנָתַתָּ שָׁם מָיִם׃
וְשַׂמְתָּ אֶת־הֶחָצֵר סָבִיב וְנָתַתָּ אֶת־מָסַךְ שַׁעַר הֶחָצֵר׃
וְלָקַחְתָּ אֶת־שֶׁמֶן הַמִּשְׁחָה וּמָשַׁחְתָּ אֶת־הַמִּשְׁכָּן וְאֶת־כָּל־אֲשֶׁר־בּוֹ וְקִדַּשְׁתָּ אֹתוֹ וְאֶת־כָּל־כֵּלָיו וְהָיָה קֹדֶשׁ׃
וּמָשַׁחְתָּ אֶת־מִזְבַּח הָעֹלָה וְאֶת־כָּל־כֵּלָיו וְקִדַּשְׁתָּ אֶת־הַמִּזְבֵּחַ וְהָיָה הַמִּזְבֵּחַ קֹדֶשׁ קָדָשִׁים׃
וּמָשַׁחְתָּ אֶת־הַכִּיֹּר וְאֶת־כַּנּוֹ וְקִדַּשְׁתָּ אֹתוֹ׃
וְהִקְרַבְתָּ אֶת־אַהֲרֹן וְאֶת־בָּנָיו אֶל־פֶּתַח אֹהֶל מוֹעֵד וְרָחַצְתָּ אֹתָם בַּמָּיִם׃
וְהִלְבַּשְׁתָּ אֶת־אַהֲרֹן אֵת בִּגְדֵי הַקֹּדֶשׁ וּמָשַׁחְתָּ אֹתוֹ וְקִדַּשְׁתָּ אֹתוֹ וְכִהֵן לִי׃
וְאֶת־בָּנָיו תַּקְרִיב וְהִלְבַּשְׁתָּ אֹתָם כֻּתֳּנֹת׃
וּמָשַׁחְתָּ אֹתָם כַּאֲשֶׁר מָשַׁחְתָּ אֶת־אֲבִיהֶם וְכִהֲנוּ לִי וְהָיְתָה לִהְיֹת לָהֶם מָשְׁחָתָם לִכְהֻנַּת עוֹלָם לְדֹרֹתָם׃
וַיַּעַשׂ מֹשֶׁה כְּכֹל אֲשֶׁר צִוָּה יְהוָה אֹתוֹ כֵּן עָשָׂה׃
וַיְהִי בַּחֹדֶשׁ הָרִאשׁוֹן בַּשָּׁנָה הַשֵּׁנִית בְּאֶחָד לַחֹדֶשׁ הוּקַם הַמִּשְׁכָּן׃
וַיָּקֶם מֹשֶׁה אֶת־הַמִּשְׁכָּן וַיִּתֵּן אֶת־אֲדָנָיו וַיָּשֶׂם אֶת־קְרָשָׁיו וַיִּתֵּן אֶת־בְּרִיחָיו וַיָּקֶם אֶת־עַמּוּדָיו׃
וַיִּפְרֹשׂ אֶת־הָאֹהֶל עַל־הַמִּשְׁכָּן וַיָּשֶׂם אֶת־מִכְסֵה הָאֹהֶל עָלָיו מִלְמָעְלָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיִּקַּח וַיִּתֵּן אֶת־הָעֵדֻת אֶל־הָאָרֹן וַיָּשֶׂם אֶת־הַבַּדִּים עַל־הָאָרֹן וַיִּתֵּן אֶת־הַכַּפֹּרֶת עַל־הָאָרֹן מִלְמָעְלָה׃
וַיָּבֵא אֶת־הָאָרֹן אֶל־הַמִּשְׁכָּן וַיָּשֶׂם אֵת פָּרֹכֶת הַמָּסָךְ וַיָּסֶךְ עַל אֲרוֹן הָעֵדוּת כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיִּתֵּן אֶת־הַשֻּׁלְחָן בְּאֹהֶל מוֹעֵד עַל יֶרֶךְ הַמִּשְׁכָּן צָפֹנָה מִחוּץ לַפָּרֹכֶת׃
וַיַּעֲרֹךְ עָלָיו עֵרֶךְ לֶחֶם לִפְנֵי יְהוָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיָּשֶׂם אֶת־הַמְּנֹרָה בְּאֹהֶל מוֹעֵד נֹכַח הַשֻּׁלְחָן עַל יֶרֶךְ הַמִּשְׁכָּן נֶגְבָּה׃
וַיַּעַל הַנֵּרֹת לִפְנֵי יְהוָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיָּשֶׂם אֶת־מִזְבַּח הַזָּהָב בְּאֹהֶל מוֹעֵד לִפְנֵי הַפָּרֹכֶת׃
וַיַּקְטֵר עָלָיו קְטֹרֶת סַמִּים כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיָּשֶׂם אֶת־מָסַךְ הַפֶּתַח לַמִּשְׁכָּן׃
וְאֵת מִזְבַּח הָעֹלָה שָׂם פֶּתַח מִשְׁכַּן אֹהֶל־מוֹעֵד וַיַּעַל עָלָיו אֶת־הָעֹלָה וְאֶת־הַמִּנְחָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיָּשֶׂם אֶת־הַכִּיֹּר בֵּין־אֹהֶל מוֹעֵד וּבֵין הַמִּזְבֵּחַ וַיִּתֵּן שָׁמָּה מַיִם לְרָחְצָה׃
וְרָחֲצוּ מִמֶּנּוּ מֹשֶׁה וְאַהֲרֹן וּבָנָיו אֶת־יְדֵיהֶם וְאֶת־רַגְלֵיהֶם׃
בְּבֹאָם אֶל־אֹהֶל מוֹעֵד וּבְקָרְבָתָם אֶל־הַמִּזְבֵּחַ יִרְחָצוּ כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיָּקֶם אֶת־הֶחָצֵר סָבִיב לַמִּשְׁכָּן וְלַמִּזְבֵּחַ וַיִּתֵּן אֶת־מָסַךְ שַׁעַר הֶחָצֵר וַיְכַל מֹשֶׁה אֶת־הַמְּלָאכָה׃
וַיְכַס הֶעָנָן אֶת־אֹהֶל מוֹעֵד וּכְבוֹד יְהוָה מָלֵא אֶת־הַמִּשְׁכָּן׃
וְלֹא־יָכֹל מֹשֶׁה לָבוֹא אֶל־אֹהֶל מוֹעֵד כִּי־שָׁכַן עָלָיו הֶעָנָן וּכְבוֹד יְהוָה מָלֵא אֶת־הַמִּשְׁכָּן׃
וּבְהֵעָלוֹת הֶעָנָן מֵעַל הַמִּשְׁכָּן יִסְעוּ בְּנֵי יִשְׂרָאֵל בְּכֹל מַסְעֵיהֶם׃
וְאִם־לֹא יֵעָלֶה הֶעָנָן וְלֹא יִסְעוּ עַד־יוֹם הֵעָלֹתוֹ׃
כִּי עֲנַן יְהוָה עַל־הַמִּשְׁכָּן יוֹמָם וְאֵשׁ תִּהְיֶה לַיְלָה בּוֹ לְעֵינֵי כָל־בֵּית־יִשְׂרָאֵל בְּכָל־מַסְעֵיהֶם׃

============================================================
### Leviticus  (/)
============================================================

Leviticus
ויקרא
Tanach with Nikkud
http://www.tanach.us/Tanach.xml

ויקרא



Chapter 1

וַיִּקְרָא אֶל־מֹשֶׁה וַיְדַבֵּר יְהוָה אֵלָיו מֵאֹהֶל מוֹעֵד לֵאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם אָדָם כִּי־יַקְרִיב מִכֶּם קָרְבָּן לַיהוָה מִן־הַבְּהֵמָה מִן־הַבָּקָר וּמִן־הַצֹּאן תַּקְרִיבוּ אֶת־קָרְבַּנְכֶם׃
אִם־עֹלָה קָרְבָּנוֹ מִן־הַבָּקָר זָכָר תָּמִים יַקְרִיבֶנּוּ אֶל־פֶּתַח אֹהֶל מוֹעֵד יַקְרִיב אֹתוֹ לִרְצֹנוֹ לִפְנֵי יְהוָה׃
וְסָמַךְ יָדוֹ עַל רֹאשׁ הָעֹלָה וְנִרְצָה לוֹ לְכַפֵּר עָלָיו׃
וְשָׁחַט אֶת־בֶּן הַבָּקָר לִפְנֵי יְהוָה וְהִקְרִיבוּ בְּנֵי אַהֲרֹן הַכֹּהֲנִים אֶת־הַדָּם וְזָרְקוּ אֶת־הַדָּם עַל־הַמִּזְבֵּחַ סָבִיב אֲשֶׁר־פֶּתַח אֹהֶל מוֹעֵד׃
וְהִפְשִׁיט אֶת־הָעֹלָה וְנִתַּח אֹתָהּ לִנְתָחֶיהָ׃
וְנָתְנוּ בְּנֵי אַהֲרֹן הַכֹּהֵן אֵשׁ עַל־הַמִּזְבֵּחַ וְעָרְכוּ עֵצִים עַל־הָאֵשׁ׃
וְעָרְכוּ בְּנֵי אַהֲרֹן הַכֹּהֲנִים אֵת הַנְּתָחִים אֶת־הָרֹאשׁ וְאֶת־הַפָּדֶר עַל־הָעֵצִים אֲשֶׁר עַל־הָאֵשׁ אֲשֶׁר עַל־הַמִּזְבֵּחַ׃
וְקִרְבּוֹ וּכְרָעָיו יִרְחַץ בַּמָּיִם וְהִקְטִיר הַכֹּהֵן אֶת־הַכֹּל הַמִּזְבֵּחָה עֹלָה אִשֵּׁה רֵיחַ־נִיחוֹחַ לַיהוָה׃
וְאִם־מִן־הַצֹּאן קָרְבָּנוֹ מִן־הַכְּשָׂבִים אוֹ מִן־הָעִזִּים לְעֹלָה זָכָר תָּמִים יַקְרִיבֶנּוּ׃
וְשָׁחַט אֹתוֹ עַל יֶרֶךְ הַמִּזְבֵּחַ צָפֹנָה לִפְנֵי יְהוָה וְזָרְקוּ בְּנֵי אַהֲרֹן הַכֹּהֲנִים אֶת־דָּמוֹ עַל־הַמִּזְבֵּחַ סָבִיב׃
וְנִתַּח אֹתוֹ לִנְתָחָיו וְאֶת־רֹאשׁוֹ וְאֶת־פִּדְרוֹ וְעָרַךְ הַכֹּהֵן אֹתָם עַל־הָעֵצִים אֲשֶׁר עַל־הָאֵשׁ אֲשֶׁר עַל־הַמִּזְבֵּחַ׃
וְהַקֶּרֶב וְהַכְּרָעַיִם יִרְחַץ בַּמָּיִם וְהִקְרִיב הַכֹּהֵן אֶת־הַכֹּל וְהִקְטִיר הַמִּזְבֵּחָה עֹלָה הוּא אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה׃
וְאִם מִן־הָעוֹף עֹלָה קָרְבָּנוֹ לַיהוָה וְהִקְרִיב מִן־הַתֹּרִים אוֹ מִן־בְּנֵי הַיּוֹנָה אֶת־קָרְבָּנוֹ׃
וְהִקְרִיבוֹ הַכֹּהֵן אֶל־הַמִּזְבֵּחַ וּמָלַק אֶת־רֹאשׁוֹ וְהִקְטִיר הַמִּזְבֵּחָה וְנִמְצָה דָמוֹ עַל קִיר הַמִּזְבֵּחַ׃
וְהֵסִיר אֶת־מֻרְאָתוֹ בְּנֹצָתָהּ וְהִשְׁלִיךְ אֹתָהּ אֵצֶל הַמִּזְבֵּחַ קֵדְמָה אֶל־מְקוֹם הַדָּשֶׁן׃
וְשִׁסַּע אֹתוֹ בִכְנָפָיו לֹא יַבְדִּיל וְהִקְטִיר אֹתוֹ הַכֹּהֵן הַמִּזְבֵּחָה עַל־הָעֵצִים אֲשֶׁר עַל־הָאֵשׁ עֹלָה הוּא אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה׃

Chapter 2

וְנֶפֶשׁ כִּי־תַקְרִיב קָרְבַּן מִנְחָה לַיהוָה סֹלֶת יִהְיֶה קָרְבָּנוֹ וְיָצַק עָלֶיהָ שֶׁמֶן וְנָתַן עָלֶיהָ לְבֹנָה׃
וֶהֱבִיאָהּ אֶל־בְּנֵי אַהֲרֹן הַכֹּהֲנִים וְקָמַץ מִשָּׁם מְלֹא קֻמְצוֹ מִסָּלְתָּהּ וּמִשַּׁמְנָהּ עַל כָּל־לְבֹנָתָהּ וְהִקְטִיר הַכֹּהֵן אֶת־אַזְכָּרָתָהּ הַמִּזְבֵּחָה אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה׃
וְהַנּוֹתֶרֶת מִן־הַמִּנְחָה לְאַהֲרֹן וּלְבָנָיו קֹדֶשׁ קָדָשִׁים מֵאִשֵּׁי יְהוָה׃
וְכִי תַקְרִב קָרְבַּן מִנְחָה מַאֲפֵה תַנּוּר סֹלֶת חַלּוֹת מַצֹּת בְּלוּלֹת בַּשֶּׁמֶן וּרְקִיקֵי מַצּוֹת מְשֻׁחִים בַּשָּׁמֶן׃
וְאִם־מִנְחָה עַל־הַמַּחֲבַת קָרְבָּנֶךָ סֹלֶת בְּלוּלָה בַשֶּׁמֶן מַצָּה תִהְיֶה׃
פָּתוֹת אֹתָהּ פִּתִּים וְיָצַקְתָּ עָלֶיהָ שָׁמֶן מִנְחָה הִוא׃
וְאִם־מִנְחַת מַרְחֶשֶׁת קָרְבָּנֶךָ סֹלֶת בַּשֶּׁמֶן תֵּעָשֶׂה׃
וְהֵבֵאתָ אֶת־הַמִּנְחָה אֲשֶׁר יֵעָשֶׂה מֵאֵלֶּה לַיהוָה וְהִקְרִיבָהּ אֶל־הַכֹּהֵן וְהִגִּישָׁהּ אֶל־הַמִּזְבֵּחַ׃
וְהֵרִים הַכֹּהֵן מִן־הַמִּנְחָה אֶת־אַזְכָּרָתָהּ וְהִקְטִיר הַמִּזְבֵּחָה אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה׃
וְהַנּוֹתֶרֶת מִן־הַמִּנְחָה לְאַהֲרֹן וּלְבָנָיו קֹדֶשׁ קָדָשִׁים מֵאִשֵּׁי יְהוָה׃
כָּל־הַמִּנְחָה אֲשֶׁר תַּקְרִיבוּ לַיהוָה לֹא תֵעָשֶׂה חָמֵץ כִּי כָל־שְׂאֹר וְכָל־דְּבַשׁ לֹא־תַקְטִירוּ מִמֶּנּוּ אִשֶּׁה לַיהוָה׃
קָרְבַּן רֵאשִׁית תַּקְרִיבוּ אֹתָם לַיהוָה וְאֶל־הַמִּזְבֵּחַ לֹא־יַעֲלוּ לְרֵיחַ נִיחֹחַ׃
וְכָל־קָרְבַּן מִנְחָתְךָ בַּמֶּלַח תִּמְלָח וְלֹא תַשְׁבִּית מֶלַח בְּרִית אֱלֹהֶיךָ מֵעַל מִנְחָתֶךָ עַל כָּל־קָרְבָּנְךָ תַּקְרִיב מֶלַח׃
וְאִם־תַּקְרִיב מִנְחַת בִּכּוּרִים לַיהוָה אָבִיב קָלוּי בָּאֵשׁ גֶּרֶשׂ כַּרְמֶל תַּקְרִיב אֵת מִנְחַת בִּכּוּרֶיךָ׃
וְנָתַתָּ עָלֶיהָ שֶׁמֶן וְשַׂמְתָּ עָלֶיהָ לְבֹנָה מִנְחָה הִוא׃
וְהִקְטִיר הַכֹּהֵן אֶת־אַזְכָּרָתָהּ מִגִּרְשָׂהּ וּמִשַּׁמְנָהּ עַל כָּל־לְבֹנָתָהּ אִשֶּׁה לַיהוָה׃

Chapter 3

וְאִם־זֶבַח שְׁלָמִים קָרְבָּנוֹ אִם מִן־הַבָּקָר הוּא מַקְרִיב אִם־זָכָר אִם־נְקֵבָה תָּמִים יַקְרִיבֶנּוּ לִפְנֵי יְהוָה׃
וְסָמַךְ יָדוֹ עַל־רֹאשׁ קָרְבָּנוֹ וּשְׁחָטוֹ פֶּתַח אֹהֶל מוֹעֵד וְזָרְקוּ בְּנֵי אַהֲרֹן הַכֹּהֲנִים אֶת־הַדָּם עַל־הַמִּזְבֵּחַ סָבִיב׃
וְהִקְרִיב מִזֶּבַח הַשְּׁלָמִים אִשֶּׁה לַיהוָה אֶת־הַחֵלֶב הַמְכַסֶּה אֶת־הַקֶּרֶב וְאֵת כָּל־הַחֵלֶב אֲשֶׁר עַל־הַקֶּרֶב׃
וְאֵת שְׁתֵּי הַכְּלָיֹת וְאֶת־הַחֵלֶב אֲשֶׁר עֲלֵהֶן אֲשֶׁר עַל־הַכְּסָלִים וְאֶת־הַיֹּתֶרֶת עַל־הַכָּבֵד עַל־הַכְּלָיוֹת יְסִירֶנָּה׃
וְהִקְטִירוּ אֹתוֹ בְנֵי־אַהֲרֹן הַמִּזְבֵּחָה עַל־הָעֹלָה אֲשֶׁר עַל־הָעֵצִים אֲשֶׁר עַל־הָאֵשׁ אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה׃
וְאִם־מִן־הַצֹּאן קָרְבָּנוֹ לְזֶבַח שְׁלָמִים לַיהוָה זָכָר אוֹ נְקֵבָה תָּמִים יַקְרִיבֶנּוּ׃
אִם־כֶּשֶׂב הוּא־מַקְרִיב אֶת־קָרְבָּנוֹ וְהִקְרִיב אֹתוֹ לִפְנֵי יְהוָה׃
וְסָמַךְ אֶת־יָדוֹ עַל־רֹאשׁ קָרְבָּנוֹ וְשָׁחַט אֹתוֹ לִפְנֵי אֹהֶל מוֹעֵד וְזָרְקוּ בְּנֵי אַהֲרֹן אֶת־דָּמוֹ עַל־הַמִּזְבֵּחַ סָבִיב׃
וְהִקְרִיב מִזֶּבַח הַשְּׁלָמִים אִשֶּׁה לַיהוָה חֶלְבּוֹ הָאַלְיָה תְמִימָה לְעֻמַּת הֶעָצֶה יְסִירֶנָּה וְאֶת־הַחֵלֶב הַמְכַסֶּה אֶת־הַקֶּרֶב וְאֵת כָּל־הַחֵלֶב אֲשֶׁר עַל־הַקֶּרֶב׃
וְאֵת שְׁתֵּי הַכְּלָיֹת וְאֶת־הַחֵלֶב אֲשֶׁר עֲלֵהֶן אֲשֶׁר עַל־הַכְּסָלִים וְאֶת־הַיֹּתֶרֶת עַל־הַכָּבֵד עַל־הַכְּלָיֹת יְסִירֶנָּה׃
וְהִקְטִירוֹ הַכֹּהֵן הַמִּזְבֵּחָה לֶחֶם אִשֶּׁה לַיהוָה׃
וְאִם עֵז קָרְבָּנוֹ וְהִקְרִיבוֹ לִפְנֵי יְהוָה׃
וְסָמַךְ אֶת־יָדוֹ עַל־רֹאשׁוֹ וְשָׁחַט אֹתוֹ לִפְנֵי אֹהֶל מוֹעֵד וְזָרְקוּ בְּנֵי אַהֲרֹן אֶת־דָּמוֹ עַל־הַמִּזְבֵּחַ סָבִיב׃
וְהִקְרִיב מִמֶּנּוּ קָרְבָּנוֹ אִשֶּׁה לַיהוָה אֶת־הַחֵלֶב הַמְכַסֶּה אֶת־הַקֶּרֶב וְאֵת כָּל־הַחֵלֶב אֲשֶׁר עַל־הַקֶּרֶב׃
וְאֵת שְׁתֵּי הַכְּלָיֹת וְאֶת־הַחֵלֶב אֲשֶׁר עֲלֵהֶן אֲשֶׁר עַל־הַכְּסָלִים וְאֶת־הַיֹּתֶרֶת עַל־הַכָּבֵד עַל־הַכְּלָיֹת יְסִירֶנָּה׃
וְהִקְטִירָם הַכֹּהֵן הַמִּזְבֵּחָה לֶחֶם אִשֶּׁה לְרֵיחַ נִיחֹחַ כָּל־חֵלֶב לַיהוָה׃
חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם בְּכֹל מוֹשְׁבֹתֵיכֶם כָּל־חֵלֶב וְכָל־דָּם לֹא תֹאכֵלוּ׃

Chapter 4

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר נֶפֶשׁ כִּי־תֶחֱטָא בִשְׁגָגָה מִכֹּל מִצְוֺת יְהוָה אֲשֶׁר לֹא תֵעָשֶׂינָה וְעָשָׂה מֵאַחַת מֵהֵנָּה׃
אִם הַכֹּהֵן הַמָּשִׁיחַ יֶחֱטָא לְאַשְׁמַת הָעָם וְהִקְרִיב עַל חַטָּאתוֹ אֲשֶׁר חָטָא פַּר בֶּן־בָּקָר תָּמִים לַיהוָה לְחַטָּאת׃
וְהֵבִיא אֶת־הַפָּר אֶל־פֶּתַח אֹהֶל מוֹעֵד לִפְנֵי יְהוָה וְסָמַךְ אֶת־יָדוֹ עַל־רֹאשׁ הַפָּר וְשָׁחַט אֶת־הַפָּר לִפְנֵי יְהוָה׃
וְלָקַח הַכֹּהֵן הַמָּשִׁיחַ מִדַּם הַפָּר וְהֵבִיא אֹתוֹ אֶל־אֹהֶל מוֹעֵד׃
וְטָבַל הַכֹּהֵן אֶת־אֶצְבָּעוֹ בַּדָּם וְהִזָּה מִן־הַדָּם שֶׁבַע פְּעָמִים לִפְנֵי יְהוָה אֶת־פְּנֵי פָּרֹכֶת הַקֹּדֶשׁ׃
וְנָתַן הַכֹּהֵן מִן־הַדָּם עַל־קַרְנוֹת מִזְבַּח קְטֹרֶת הַסַּמִּים לִפְנֵי יְהוָה אֲשֶׁר בְּאֹהֶל מוֹעֵד וְאֵת כָּל־דַּם הַפָּר יִשְׁפֹּךְ אֶל־יְסוֹד מִזְבַּח הָעֹלָה אֲשֶׁר־פֶּתַח אֹהֶל מוֹעֵד׃
וְאֶת־כָּל־חֵלֶב פַּר הַחַטָּאת יָרִים מִמֶּנּוּ אֶת־הַחֵלֶב הַמְכַסֶּה עַל־הַקֶּרֶב וְאֵת כָּל־הַחֵלֶב אֲשֶׁר עַל־הַקֶּרֶב׃
וְאֵת שְׁתֵּי הַכְּלָיֹת וְאֶת־הַחֵלֶב אֲשֶׁר עֲלֵיהֶן אֲשֶׁר עַל־הַכְּסָלִים וְאֶת־הַיֹּתֶרֶת עַל־הַכָּבֵד עַל־הַכְּלָיוֹת יְסִירֶנָּה׃
כַּאֲשֶׁר יוּרַם מִשּׁוֹר זֶבַח הַשְּׁלָמִים וְהִקְטִירָם הַכֹּהֵן עַל מִזְבַּח הָעֹלָה׃
וְאֶת־עוֹר הַפָּר וְאֶת־כָּל־בְּשָׂרוֹ עַל־רֹאשׁוֹ וְעַל־כְּרָעָיו וְקִרְבּוֹ וּפִרְשׁוֹ׃
וְהוֹצִיא אֶת־כָּל־הַפָּר אֶל־מִחוּץ לַמַּחֲנֶה אֶל־מָקוֹם טָהוֹר אֶל־שֶׁפֶךְ הַדֶּשֶׁן וְשָׂרַף אֹתוֹ עַל־עֵצִים בָּאֵשׁ עַל־שֶׁפֶךְ הַדֶּשֶׁן יִשָּׂרֵף׃
וְאִם כָּל־עֲדַת יִשְׂרָאֵל יִשְׁגּוּ וְנֶעְלַם דָּבָר מֵעֵינֵי הַקָּהָל וְעָשׂוּ אַחַת מִכָּל־מִצְוֺת יְהוָה אֲשֶׁר לֹא־תֵעָשֶׂינָה וְאָשֵׁמוּ׃
וְנוֹדְעָה הַחַטָּאת אֲשֶׁר חָטְאוּ עָלֶיהָ וְהִקְרִיבוּ הַקָּהָל פַּר בֶּן־בָּקָר לְחַטָּאת וְהֵבִיאוּ אֹתוֹ לִפְנֵי אֹהֶל מוֹעֵד׃
וְסָמְכוּ זִקְנֵי הָעֵדָה אֶת־יְדֵיהֶם עַל־רֹאשׁ הַפָּר לִפְנֵי יְהוָה וְשָׁחַט אֶת־הַפָּר לִפְנֵי יְהוָה׃
וְהֵבִיא הַכֹּהֵן הַמָּשִׁיחַ מִדַּם הַפָּר אֶל־אֹהֶל מוֹעֵד׃
וְטָבַל הַכֹּהֵן אֶצְבָּעוֹ מִן־הַדָּם וְהִזָּה שֶׁבַע פְּעָמִים לִפְנֵי יְהוָה אֵת פְּנֵי הַפָּרֹכֶת׃
וּמִן־הַדָּם יִתֵּן עַל־קַרְנֹת הַמִּזְבֵּחַ אֲשֶׁר לִפְנֵי יְהוָה אֲשֶׁר בְּאֹהֶל מוֹעֵד וְאֵת כָּל־הַדָּם יִשְׁפֹּךְ אֶל־יְסוֹד מִזְבַּח הָעֹלָה אֲשֶׁר־פֶּתַח אֹהֶל מוֹעֵד׃
וְאֵת כָּל־חֶלְבּוֹ יָרִים מִמֶּנּוּ וְהִקְטִיר הַמִּזְבֵּחָה׃
וְעָשָׂה לַפָּר כַּאֲשֶׁר עָשָׂה לְפַר הַחַטָּאת כֵּן יַעֲשֶׂה־לּוֹ וְכִפֶּר עֲלֵהֶם הַכֹּהֵן וְנִסְלַח לָהֶם׃
וְהוֹצִיא אֶת־הַפָּר אֶל־מִחוּץ לַמַּחֲנֶה וְשָׂרַף אֹתוֹ כַּאֲשֶׁר שָׂרַף אֵת הַפָּר הָרִאשׁוֹן חַטַּאת הַקָּהָל הוּא׃
אֲשֶׁר נָשִׂיא יֶחֱטָא וְעָשָׂה אַחַת מִכָּל־מִצְוֺת יְהוָה אֱלֹהָיו אֲשֶׁר לֹא־תֵעָשֶׂינָה בִּשְׁגָגָה וְאָשֵׁם׃
אוֹ־הוֹדַע אֵלָיו חַטָּאתוֹ אֲשֶׁר חָטָא בָּהּ וְהֵבִיא אֶת־קָרְבָּנוֹ שְׂעִיר עִזִּים זָכָר תָּמִים׃
וְסָמַךְ יָדוֹ עַל־רֹאשׁ הַשָּׂעִיר וְשָׁחַט אֹתוֹ בִּמְקוֹם אֲשֶׁר־יִשְׁחַט אֶת־הָעֹלָה לִפְנֵי יְהוָה חַטָּאת הוּא׃
וְלָקַח הַכֹּהֵן מִדַּם הַחַטָּאת בְּאֶצְבָּעוֹ וְנָתַן עַל־קַרְנֹת מִזְבַּח הָעֹלָה וְאֶת־דָּמוֹ יִשְׁפֹּךְ אֶל־יְסוֹד מִזְבַּח הָעֹלָה׃
וְאֶת־כָּל־חֶלְבּוֹ יַקְטִיר הַמִּזְבֵּחָה כְּחֵלֶב זֶבַח הַשְּׁלָמִים וְכִפֶּר עָלָיו הַכֹּהֵן מֵחַטָּאתוֹ וְנִסְלַח לוֹ׃
וְאִם־נֶפֶשׁ אַחַת תֶּחֱטָא בִשְׁגָגָה מֵעַם הָאָרֶץ בַּעֲשֹׂתָהּ אַחַת מִמִּצְוֺת יְהוָה אֲשֶׁר לֹא־תֵעָשֶׂינָה וְאָשֵׁם׃
אוֹ הוֹדַע אֵלָיו חַטָּאתוֹ אֲשֶׁר חָטָא וְהֵבִיא קָרְבָּנוֹ שְׂעִירַת עִזִּים תְּמִימָה נְקֵבָה עַל־חַטָּאתוֹ אֲשֶׁר חָטָא׃
וְסָמַךְ אֶת־יָדוֹ עַל רֹאשׁ הַחַטָּאת וְשָׁחַט אֶת־הַחַטָּאת בִּמְקוֹם הָעֹלָה׃
וְלָקַח הַכֹּהֵן מִדָּמָהּ בְּאֶצְבָּעוֹ וְנָתַן עַל־קַרְנֹת מִזְבַּח הָעֹלָה וְאֶת־כָּל־דָּמָהּ יִשְׁפֹּךְ אֶל־יְסוֹד הַמִּזְבֵּחַ׃
וְאֶת־כָּל־חֶלְבָּהּ יָסִיר כַּאֲשֶׁר הוּסַר חֵלֶב מֵעַל זֶבַח הַשְּׁלָמִים וְהִקְטִיר הַכֹּהֵן הַמִּזְבֵּחָה לְרֵיחַ נִיחֹחַ לַיהוָה וְכִפֶּר עָלָיו הַכֹּהֵן וְנִסְלַח לוֹ׃
וְאִם־כֶּבֶשׂ יָבִיא קָרְבָּנוֹ לְחַטָּאת נְקֵבָה תְמִימָה יְבִיאֶנָּה׃
וְסָמַךְ אֶת־יָדוֹ עַל רֹאשׁ הַחַטָּאת וְשָׁחַט אֹתָהּ לְחַטָּאת בִּמְקוֹם אֲשֶׁר יִשְׁחַט אֶת־הָעֹלָה׃
וְלָקַח הַכֹּהֵן מִדַּם הַחַטָּאת בְּאֶצְבָּעוֹ וְנָתַן עַל־קַרְנֹת מִזְבַּח הָעֹלָה וְאֶת־כָּל־דָּמָהּ יִשְׁפֹּךְ אֶל־יְסוֹד הַמִּזְבֵּחַ׃
וְאֶת־כָּל־חֶלְבָּה יָסִיר כַּאֲשֶׁר יוּסַר חֵלֶב־הַכֶּשֶׂב מִזֶּבַח הַשְּׁלָמִים וְהִקְטִיר הַכֹּהֵן אֹתָם הַמִּזְבֵּחָה עַל אִשֵּׁי יְהוָה וְכִפֶּר עָלָיו הַכֹּהֵן עַל־חַטָּאתוֹ אֲשֶׁר־חָטָא וְנִסְלַח לוֹ׃

Chapter 5

וְנֶפֶשׁ כִּי־תֶחֱטָא וְשָׁמְעָה קוֹל אָלָה וְהוּא עֵד אוֹ רָאָה אוֹ יָדָע אִם־לוֹא יַגִּיד וְנָשָׂא עֲוֺנוֹ׃
אוֹ נֶפֶשׁ אֲשֶׁר תִּגַּע בְּכָל־דָּבָר טָמֵא אוֹ בְנִבְלַת חַיָּה טְמֵאָה אוֹ בְּנִבְלַת בְּהֵמָה טְמֵאָה אוֹ בְּנִבְלַת שֶׁרֶץ טָמֵא וְנֶעְלַם מִמֶּנּוּ וְהוּא טָמֵא וְאָשֵׁם׃
אוֹ כִי יִגַּע בְּטֻמְאַת אָדָם לְכֹל טֻמְאָתוֹ אֲשֶׁר יִטְמָא בָּהּ וְנֶעְלַם מִמֶּנּוּ וְהוּא יָדַע וְאָשֵׁם׃
אוֹ נֶפֶשׁ כִּי תִשָּׁבַע לְבַטֵּא בִשְׂפָתַיִם לְהָרַע אוֹ לְהֵיטִיב לְכֹל אֲשֶׁר יְבַטֵּא הָאָדָם בִּשְׁבֻעָה וְנֶעְלַם מִמֶּנּוּ וְהוּא־יָדַע וְאָשֵׁם לְאַחַת מֵאֵלֶּה׃
וְהָיָה כִי־יֶאְשַׁם לְאַחַת מֵאֵלֶּה וְהִתְוַדָּה אֲשֶׁר חָטָא עָלֶיהָ׃
וְהֵבִיא אֶת־אֲשָׁמוֹ לַיהוָה עַל חַטָּאתוֹ אֲשֶׁר חָטָא נְקֵבָה מִן־הַצֹּאן כִּשְׂבָּה אוֹ־שְׂעִירַת עִזִּים לְחַטָּאת וְכִפֶּר עָלָיו הַכֹּהֵן מֵחַטָּאתוֹ׃
וְאִם־לֹא תַגִּיע יָדוֹ דֵּי שֶׂה וְהֵבִיא אֶת־אֲשָׁמוֹ אֲשֶׁר חָטָא שְׁתֵּי תֹרִים אוֹ־שְׁנֵי בְנֵי־יוֹנָה לַיהוָה אֶחָד לְחַטָּאת וְאֶחָד לְעֹלָה׃
וְהֵבִיא אֹתָם אֶל־הַכֹּהֵן וְהִקְרִיב אֶת־אֲשֶׁר לַחַטָּאת רִאשׁוֹנָה וּמָלַק אֶת־רֹאשׁוֹ מִמּוּל עָרְפּוֹ וְלֹא יַבְדִּיל׃
וְהִזָּה מִדַּם הַחַטָּאת עַל־קִיר הַמִּזְבֵּחַ וְהַנִּשְׁאָר בַּדָּם יִמָּצֵה אֶל־יְסוֹד הַמִּזְבֵּחַ חַטָּאת הוּא׃
וְאֶת־הַשֵּׁנִי יַעֲשֶׂה עֹלָה כַּמִּשְׁפָּט וְכִפֶּר עָלָיו הַכֹּהֵן מֵחַטָּאתוֹ אֲשֶׁר־חָטָא וְנִסְלַח לוֹ׃
וְאִם־לֹא תַשִּׂיג יָדוֹ לִשְׁתֵּי תֹרִים אוֹ לִשְׁנֵי בְנֵי־יוֹנָה וְהֵבִיא אֶת־קָרְבָּנוֹ אֲשֶׁר חָטָא עֲשִׂירִת הָאֵפָה סֹלֶת לְחַטָּאת לֹא־יָשִׂים עָלֶיהָ שֶׁמֶן וְלֹא־יִתֵּן עָלֶיהָ לְבֹנָה כִּי חַטָּאת הִיא׃
וֶהֱבִיאָהּ אֶל־הַכֹּהֵן וְקָמַץ הַכֹּהֵן מִמֶּנָּה מְלוֹא קֻמְצוֹ אֶת־אַזְכָּרָתָה וְהִקְטִיר הַמִּזְבֵּחָה עַל אִשֵּׁי יְהוָה חַטָּאת הִוא׃
וְכִפֶּר עָלָיו הַכֹּהֵן עַל־חַטָּאתוֹ אֲשֶׁר־חָטָא מֵאַחַת מֵאֵלֶּה וְנִסְלַח לוֹ וְהָיְתָה לַכֹּהֵן כַּמִּנְחָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
נֶפֶשׁ כִּי־תִמְעֹל מַעַל וְחָטְאָה בִּשְׁגָגָה מִקָּדְשֵׁי יְהוָה וְהֵבִיא אֶת־אֲשָׁמוֹ לַיהוָה אַיִל תָּמִים מִן־הַצֹּאן בְּעֶרְכְּךָ כֶּסֶף־שְׁקָלִים בְּשֶׁקֶל־הַקֹּדֶשׁ לְאָשָׁם׃
וְאֵת אֲשֶׁר חָטָא מִן־הַקֹּדֶשׁ יְשַׁלֵּם וְאֶת־חֲמִישִׁתוֹ יוֹסֵף עָלָיו וְנָתַן אֹתוֹ לַכֹּהֵן וְהַכֹּהֵן יְכַפֵּר עָלָיו בְּאֵיל הָאָשָׁם וְנִסְלַח לוֹ׃
וְאִם־נֶפֶשׁ כִּי תֶחֱטָא וְעָשְׂתָה אַחַת מִכָּל־מִצְוֺת יְהוָה אֲשֶׁר לֹא תֵעָשֶׂינָה וְלֹא־יָדַע וְאָשֵׁם וְנָשָׂא עֲוֺנוֹ׃
וְהֵבִיא אַיִל תָּמִים מִן־הַצֹּאן בְּעֶרְכְּךָ לְאָשָׁם אֶל־הַכֹּהֵן וְכִפֶּר עָלָיו הַכֹּהֵן עַל שִׁגְגָתוֹ אֲשֶׁר־שָׁגָג וְהוּא לֹא־יָדַע וְנִסְלַח לוֹ׃
אָשָׁם הוּא אָשֹׁם אָשַׁם לַיהוָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
נֶפֶשׁ כִּי תֶחֱטָא וּמָעֲלָה מַעַל בַּיהוָה וְכִחֵשׁ בַּעֲמִיתוֹ בְּפִקָּדוֹן אוֹ־בִתְשׂוּמֶת יָד אוֹ בְגָזֵל אוֹ עָשַׁק אֶת־עֲמִיתוֹ׃
אוֹ־מָצָא אֲבֵדָה וְכִחֶשׁ בָּהּ וְנִשְׁבַּע עַל־שָׁקֶר עַל־אַחַת מִכֹּל אֲשֶׁר־יַעֲשֶׂה הָאָדָם לַחֲטֹא בָהֵנָּה׃
וְהָיָה כִּי־יֶחֱטָא וְאָשֵׁם וְהֵשִׁיב אֶת־הַגְּזֵלָה אֲשֶׁר גָּזָל אוֹ אֶת־הָעֹשֶׁק אֲשֶׁר עָשָׁק אוֹ אֶת־הַפִּקָּדוֹן אֲשֶׁר הָפְקַד אִתּוֹ אוֹ אֶת־הָאֲבֵדָה אֲשֶׁר מָצָא׃
אוֹ מִכֹּל אֲשֶׁר־יִשָּׁבַע עָלָיו לַשֶּׁקֶר וְשִׁלַּם אֹתוֹ בְּרֹאשׁוֹ וַחֲמִשִׁתָיו יֹסֵף עָלָיו לַאֲשֶׁר הוּא לוֹ יִתְּנֶנּוּ בְּיוֹם אַשְׁמָתוֹ׃
וְאֶת־אֲשָׁמוֹ יָבִיא לַיהוָה אַיִל תָּמִים מִן־הַצֹּאן בְּעֶרְכְּךָ לְאָשָׁם אֶל־הַכֹּהֵן׃
וְכִפֶּר עָלָיו הַכֹּהֵן לִפְנֵי יְהוָה וְנִסְלַח לוֹ עַל־אַחַת מִכֹּל אֲשֶׁר־יַעֲשֶׂה לְאַשְׁמָה בָהּ׃

Chapter 6

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
צַו אֶת־אַהֲרֹן וְאֶת־בָּנָיו לֵאמֹר זֹאת תּוֹרַת הָעֹלָה הִוא הָעֹלָה עַל מוֹקְדָה עַל־הַמִּזְבֵּחַ כָּל־הַלַּיְלָה עַד־הַבֹּקֶר וְאֵשׁ הַמִּזְבֵּחַ תּוּקַד בּוֹ׃
וְלָבַשׁ הַכֹּהֵן מִדּוֹ בַד וּמִכְנְסֵי־בַד יִלְבַּשׁ עַל־בְּשָׂרוֹ וְהֵרִים אֶת־הַדֶּשֶׁן אֲשֶׁר תֹּאכַל הָאֵשׁ אֶת־הָעֹלָה עַל־הַמִּזְבֵּחַ וְשָׂמוֹ אֵצֶל הַמִּזְבֵּחַ׃
וּפָשַׁט אֶת־בְּגָדָיו וְלָבַשׁ בְּגָדִים אֲחֵרִים וְהוֹצִיא אֶת־הַדֶּשֶׁן אֶל־מִחוּץ לַמַּחֲנֶה אֶל־מָקוֹם טָהוֹר׃
וְהָאֵשׁ עַל־הַמִּזְבֵּחַ תּוּקַד־בּוֹ לֹא תִכְבֶּה וּבִעֵר עָלֶיהָ הַכֹּהֵן עֵצִים בַּבֹּקֶר בַּבֹּקֶר וְעָרַךְ עָלֶיהָ הָעֹלָה וְהִקְטִיר עָלֶיהָ חֶלְבֵי הַשְּׁלָמִים׃
אֵשׁ תָּמִיד תּוּקַד עַל־הַמִּזְבֵּחַ לֹא תִכְבֶה׃
וְזֹאת תּוֹרַת הַמִּנְחָה הַקְרֵב אֹתָהּ בְּנֵי־אַהֲרֹן לִפְנֵי יְהוָה אֶל־פְּנֵי הַמִּזְבֵּחַ׃
וְהֵרִים מִמֶּנּוּ בְּקֻמְצוֹ מִסֹּלֶת הַמִּנְחָה וּמִשַּׁמְנָהּ וְאֵת כָּל־הַלְּבֹנָה אֲשֶׁר עַל־הַמִּנְחָה וְהִקְטִיר הַמִּזְבֵּחַ רֵיחַ נִיחֹחַ אַזְכָּרָתָהּ לַיהוָה׃
וְהַנּוֹתֶרֶת מִמֶּנָּה יֹאכְלוּ אַהֲרֹן וּבָנָיו מַצּוֹת תֵּאָכֵל בְּמָקוֹם קָדֹשׁ בַּחֲצַר אֹהֶל־מוֹעֵד יֹאכְלוּהָ׃
לֹא תֵאָפֶה חָמֵץ חֶלְקָם נָתַתִּי אֹתָהּ מֵאִשָּׁי קֹדֶשׁ קָדָשִׁים הִוא כַּחַטָּאת וְכָאָשָׁם׃
כָּל־זָכָר בִּבְנֵי אַהֲרֹן יֹאכֲלֶנָּה חָק־עוֹלָם לְדֹרֹתֵיכֶם מֵאִשֵּׁי יְהוָה כֹּל אֲשֶׁר־יִגַּע בָּהֶם יִקְדָּשׁ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
זֶה קָרְבַּן אַהֲרֹן וּבָנָיו אֲשֶׁר־יַקְרִיבוּ לַיהוָה בְּיוֹם הִמָּשַׁח אֹתוֹ עֲשִׂירִת הָאֵפָה סֹלֶת מִנְחָה תָּמִיד מַחֲצִיתָהּ בַּבֹּקֶר וּמַחֲצִיתָהּ בָּעָרֶב׃
עַל־מַחֲבַת בַּשֶּׁמֶן תֵּעָשֶׂה מֻרְבֶּכֶת תְּבִיאֶנָּה תֻּפִינֵי מִנְחַת פִּתִּים תַּקְרִיב רֵיחַ־נִיחֹחַ לַיהוָה׃
וְהַכֹּהֵן הַמָּשִׁיחַ תַּחְתָּיו מִבָּנָיו יַעֲשֶׂה אֹתָהּ חָק־עוֹלָם לַיהוָה כָּלִיל תָּקְטָר׃
וְכָל־מִנְחַת כֹּהֵן כָּלִיל תִּהְיֶה לֹא תֵאָכֵל׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־אַהֲרֹן וְאֶל־בָּנָיו לֵאמֹר זֹאת תּוֹרַת הַחַטָּאת בִּמְקוֹם אֲשֶׁר תִּשָּׁחֵט הָעֹלָה תִּשָּׁחֵט הַחַטָּאת לִפְנֵי יְהוָה קֹדֶשׁ קָדָשִׁים הִוא׃
הַכֹּהֵן הַמְחַטֵּא אֹתָהּ יֹאכֲלֶנָּה בְּמָקוֹם קָדֹשׁ תֵּאָכֵל בַּחֲצַר אֹהֶל מוֹעֵד׃
כֹּל אֲשֶׁר־יִגַּע בִּבְשָׂרָהּ יִקְדָּשׁ וַאֲשֶׁר יִזֶּה מִדָּמָהּ עַל־הַבֶּגֶד אֲשֶׁר יִזֶּה עָלֶיהָ תְּכַבֵּס בְּמָקוֹם קָדֹשׁ׃
וּכְלִי־חֶרֶשׂ אֲשֶׁר תְּבֻשַּׁל־בּוֹ יִשָּׁבֵר וְאִם־בִּכְלִי נְחֹשֶׁת בֻּשָּׁלָה וּמֹרַק וְשֻׁטַּף בַּמָּיִם׃
כָּל־זָכָר בַּכֹּהֲנִים יֹאכַל אֹתָהּ קֹדֶשׁ קָדָשִׁים הִוא׃
וְכָל־חַטָּאת אֲשֶׁר יוּבָא מִדָּמָהּ אֶל־אֹהֶל מוֹעֵד לְכַפֵּר בַּקֹּדֶשׁ לֹא תֵאָכֵל בָּאֵשׁ תִּשָּׂרֵף׃

Chapter 7

וְזֹאת תּוֹרַת הָאָשָׁם קֹדֶשׁ קָדָשִׁים הוּא׃
בִּמְקוֹם אֲשֶׁר יִשְׁחֲטוּ אֶת־הָעֹלָה יִשְׁחֲטוּ אֶת־הָאָשָׁם וְאֶת־דָּמוֹ יִזְרֹק עַל־הַמִּזְבֵּחַ סָבִיב׃
וְאֵת כָּל־חֶלְבּוֹ יַקְרִיב מִמֶּנּוּ אֵת הָאַלְיָה וְאֶת־הַחֵלֶב הַמְכַסֶּה אֶת־הַקֶּרֶב׃
וְאֵת שְׁתֵּי הַכְּלָיֹת וְאֶת־הַחֵלֶב אֲשֶׁר עֲלֵיהֶן אֲשֶׁר עַל־הַכְּסָלִים וְאֶת־הַיֹּתֶרֶת עַל־הַכָּבֵד עַל־הַכְּלָיֹת יְסִירֶנָּה׃
וְהִקְטִיר אֹתָם הַכֹּהֵן הַמִּזְבֵּחָה אִשֶּׁה לַיהוָה אָשָׁם הוּא׃
כָּל־זָכָר בַּכֹּהֲנִים יֹאכְלֶנּוּ בְּמָקוֹם קָדוֹשׁ יֵאָכֵל קֹדֶשׁ קָדָשִׁים הוּא׃
כַּחַטָּאת כָּאָשָׁם תּוֹרָה אַחַת לָהֶם הַכֹּהֵן אֲשֶׁר יְכַפֶּר־בּוֹ לוֹ יִהְיֶה׃
וְהַכֹּהֵן הַמַּקְרִיב אֶת־עֹלַת אִישׁ עוֹר הָעֹלָה אֲשֶׁר הִקְרִיב לַכֹּהֵן לוֹ יִהְיֶה׃
וְכָל־מִנְחָה אֲשֶׁר תֵּאָפֶה בַּתַּנּוּר וְכָל־נַעֲשָׂה בַמַּרְחֶשֶׁת וְעַל־מַחֲבַת לַכֹּהֵן הַמַּקְרִיב אֹתָהּ לוֹ תִהְיֶה׃
וְכָל־מִנְחָה בְלוּלָה־בַשֶּׁמֶן וַחֲרֵבָה לְכָל־בְּנֵי אַהֲרֹן תִּהְיֶה אִישׁ כְּאָחִיו׃
וְזֹאת תּוֹרַת זֶבַח הַשְּׁלָמִים אֲשֶׁר יַקְרִיב לַיהוָה׃
אִם עַל־תּוֹדָה יַקְרִיבֶנּוּ וְהִקְרִיב עַל־זֶבַח הַתּוֹדָה חַלּוֹת מַצּוֹת בְּלוּלֹת בַּשֶּׁמֶן וּרְקִיקֵי מַצּוֹת מְשֻׁחִים בַּשָּׁמֶן וְסֹלֶת מֻרְבֶּכֶת חַלֹּת בְּלוּלֹת בַּשָּׁמֶן׃
עַל־חַלֹּת לֶחֶם חָמֵץ יַקְרִיב קָרְבָּנוֹ עַל־זֶבַח תּוֹדַת שְׁלָמָיו׃
וְהִקְרִיב מִמֶּנּוּ אֶחָד מִכָּל־קָרְבָּן תְּרוּמָה לַיהוָה לַכֹּהֵן הַזֹּרֵק אֶת־דַּם הַשְּׁלָמִים לוֹ יִהְיֶה׃
וּבְשַׂר זֶבַח תּוֹדַת שְׁלָמָיו בְּיוֹם קָרְבָּנוֹ יֵאָכֵל לֹא־יַנִּיחַ מִמֶּנּוּ עַד־בֹּקֶר׃
וְאִם־נֶדֶר אוֹ נְדָבָה זֶבַח קָרְבָּנוֹ בְּיוֹם הַקְרִיבוֹ אֶת־זִבְחוֹ יֵאָכֵל וּמִמָּחֳרָת וְהַנּוֹתָר מִמֶּנּוּ יֵאָכֵל׃
וְהַנּוֹתָר מִבְּשַׂר הַזָּבַח בַּיּוֹם הַשְּׁלִישִׁי בָּאֵשׁ יִשָּׂרֵף׃
וְאִם הֵאָכֹל יֵאָכֵל מִבְּשַׂר־זֶבַח שְׁלָמָיו בַּיּוֹם הַשְּׁלִישִׁי לֹא יֵרָצֶה הַמַּקְרִיב אֹתוֹ לֹא יֵחָשֵׁב לוֹ פִּגּוּל יִהְיֶה וְהַנֶּפֶשׁ הָאֹכֶלֶת מִמֶּנּוּ עֲוֺנָהּ תִּשָּׂא׃
וְהַבָּשָׂר אֲשֶׁר־יִגַּע בְּכָל־טָמֵא לֹא יֵאָכֵל בָּאֵשׁ יִשָּׂרֵף וְהַבָּשָׂר כָּל־טָהוֹר יֹאכַל בָּשָׂר׃
וְהַנֶּפֶשׁ אֲשֶׁר־תֹּאכַל בָּשָׂר מִזֶּבַח הַשְּׁלָמִים אֲשֶׁר לַיהוָה וְטֻמְאָתוֹ עָלָיו וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מֵעַמֶּיהָ׃
וְנֶפֶשׁ כִּי־תִגַּע בְּכָל־טָמֵא בְּטֻמְאַת אָדָם אוֹ בִּבְהֵמָה טְמֵאָה אוֹ בְּכָל־שֶׁקֶץ טָמֵא וְאָכַל מִבְּשַׂר־זֶבַח הַשְּׁלָמִים אֲשֶׁר לַיהוָה וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מֵעַמֶּיהָ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר כָּל־חֵלֶב שׁוֹר וְכֶשֶׂב וָעֵז לֹא תֹאכֵלוּ׃
וְחֵלֶב נְבֵלָה וְחֵלֶב טְרֵפָה יֵעָשֶׂה לְכָל־מְלָאכָה וְאָכֹל לֹא תֹאכְלֻהוּ׃
כִּי כָּל־אֹכֵל חֵלֶב מִן־הַבְּהֵמָה אֲשֶׁר יַקְרִיב מִמֶּנָּה אִשֶּׁה לַיהוָה וְנִכְרְתָה הַנֶּפֶשׁ הָאֹכֶלֶת מֵעַמֶּיהָ׃
וְכָל־דָּם לֹא תֹאכְלוּ בְּכֹל מוֹשְׁבֹתֵיכֶם לָעוֹף וְלַבְּהֵמָה׃
כָּל־נֶפֶשׁ אֲשֶׁר־תֹּאכַל כָּל־דָּם וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מֵעַמֶּיהָ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר הַמַּקְרִיב אֶת־זֶבַח שְׁלָמָיו לַיהוָה יָבִיא אֶת־קָרְבָּנוֹ לַיהוָה מִזֶּבַח שְׁלָמָיו׃
יָדָיו תְּבִיאֶינָה אֵת אִשֵּׁי יְהוָה אֶת־הַחֵלֶב עַל־הֶחָזֶה יְבִיאֶנּוּ אֵת הֶחָזֶה לְהָנִיף אֹתוֹ תְּנוּפָה לִפְנֵי יְהוָה׃
וְהִקְטִיר הַכֹּהֵן אֶת־הַחֵלֶב הַמִּזְבֵּחָה וְהָיָה הֶחָזֶה לְאַהֲרֹן וּלְבָנָיו׃
וְאֵת שׁוֹק הַיָּמִין תִּתְּנוּ תְרוּמָה לַכֹּהֵן מִזִּבְחֵי שַׁלְמֵיכֶם׃
הַמַּקְרִיב אֶת־דַּם הַשְּׁלָמִים וְאֶת־הַחֵלֶב מִבְּנֵי אַהֲרֹן לוֹ תִהְיֶה שׁוֹק הַיָּמִין לְמָנָה׃
כִּי אֶת־חֲזֵה הַתְּנוּפָה וְאֵת שׁוֹק הַתְּרוּמָה לָקַחְתִּי מֵאֵת בְּנֵי־יִשְׂרָאֵל מִזִּבְחֵי שַׁלְמֵיהֶם וָאֶתֵּן אֹתָם לְאַהֲרֹן הַכֹּהֵן וּלְבָנָיו לְחָק־עוֹלָם מֵאֵת בְּנֵי יִשְׂרָאֵל׃
זֹאת מִשְׁחַת אַהֲרֹן וּמִשְׁחַת בָּנָיו מֵאִשֵּׁי יְהוָה בְּיוֹם הִקְרִיב אֹתָם לְכַהֵן לַיהוָה׃
אֲשֶׁר צִוָּה יְהוָה לָתֵת לָהֶם בְּיוֹם מָשְׁחוֹ אֹתָם מֵאֵת בְּנֵי יִשְׂרָאֵל חֻקַּת עוֹלָם לְדֹרֹתָם׃
זֹאת הַתּוֹרָה לָעֹלָה לַמִּנְחָה וְלַחַטָּאת וְלָאָשָׁם וְלַמִּלּוּאִים וּלְזֶבַח הַשְּׁלָמִים׃
אֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה בְּהַר סִינָי בְּיוֹם צַוֺּתוֹ אֶת־בְּנֵי יִשְׂרָאֵל לְהַקְרִיב אֶת־קָרְבְּנֵיהֶם לַיהוָה בְּמִדְבַּר סִינָי׃

Chapter 8

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
קַח אֶת־אַהֲרֹן וְאֶת־בָּנָיו אִתּוֹ וְאֵת הַבְּגָדִים וְאֵת שֶׁמֶן הַמִּשְׁחָה וְאֵת פַּר הַחַטָּאת וְאֵת שְׁנֵי הָאֵילִים וְאֵת סַל הַמַּצּוֹת׃
וְאֵת כָּל־הָעֵדָה הַקְהֵל אֶל־פֶּתַח אֹהֶל מוֹעֵד׃
וַיַּעַשׂ מֹשֶׁה כַּאֲשֶׁר צִוָּה יְהוָה אֹתוֹ וַתִּקָּהֵל הָעֵדָה אֶל־פֶּתַח אֹהֶל מוֹעֵד׃
וַיֹּאמֶר מֹשֶׁה אֶל־הָעֵדָה זֶה הַדָּבָר אֲשֶׁר־צִוָּה יְהוָה לַעֲשׂוֹת׃
וַיַּקְרֵב מֹשֶׁה אֶת־אַהֲרֹן וְאֶת־בָּנָיו וַיִּרְחַץ אֹתָם בַּמָּיִם׃
וַיִּתֵּן עָלָיו אֶת־הַכֻּתֹּנֶת וַיַּחְגֹּר אֹתוֹ בָּאַבְנֵט וַיַּלְבֵּשׁ אֹתוֹ אֶת־הַמְּעִיל וַיִּתֵּן עָלָיו אֶת־הָאֵפֹד וַיַּחְגֹּר אֹתוֹ בְּחֵשֶׁב הָאֵפֹד וַיֶּאְפֹּד לוֹ בּוֹ׃
וַיָּשֶׂם עָלָיו אֶת־הַחֹשֶׁן וַיִּתֵּן אֶל־הַחֹשֶׁן אֶת־הָאוּרִים וְאֶת־הַתֻּמִּים׃
וַיָּשֶׂם אֶת־הַמִּצְנֶפֶת עַל־רֹאשׁוֹ וַיָּשֶׂם עַל־הַמִּצְנֶפֶת אֶל־מוּל פָּנָיו אֵת צִיץ הַזָּהָב נֵזֶר הַקֹּדֶשׁ כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיִּקַּח מֹשֶׁה אֶת־שֶׁמֶן הַמִּשְׁחָה וַיִּמְשַׁח אֶת־הַמִּשְׁכָּן וְאֶת־כָּל־אֲשֶׁר־בּוֹ וַיְקַדֵּשׁ אֹתָם׃
וַיַּז מִמֶּנּוּ עַל־הַמִּזְבֵּחַ שֶׁבַע פְּעָמִים וַיִּמְשַׁח אֶת־הַמִּזְבֵּחַ וְאֶת־כָּל־כֵּלָיו וְאֶת־הַכִּיֹּר וְאֶת־כַּנּוֹ לְקַדְּשָׁם׃
וַיִּצֹק מִשֶּׁמֶן הַמִּשְׁחָה עַל רֹאשׁ אַהֲרֹן וַיִּמְשַׁח אֹתוֹ לְקַדְּשׁוֹ׃
וַיַּקְרֵב מֹשֶׁה אֶת־בְּנֵי אַהֲרֹן וַיַּלְבִּשֵׁם כֻּתֳּנֹת וַיַּחְגֹּר אֹתָם אַבְנֵט וַיַּחֲבֹשׁ לָהֶם מִגְבָּעוֹת כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּגֵּשׁ אֵת פַּר הַחַטָּאת וַיִּסְמֹךְ אַהֲרֹן וּבָנָיו אֶת־יְדֵיהֶם עַל־רֹאשׁ פַּר הַחַטָּאת׃
וַיִּשְׁחָט וַיִּקַּח מֹשֶׁה אֶת־הַדָּם וַיִּתֵּן עַל־קַרְנוֹת הַמִּזְבֵּחַ סָבִיב בְּאֶצְבָּעוֹ וַיְחַטֵּא אֶת־הַמִּזְבֵּחַ וְאֶת־הַדָּם יָצַק אֶל־יְסוֹד הַמִּזְבֵּחַ וַיְקַדְּשֵׁהוּ לְכַפֵּר עָלָיו׃
וַיִּקַּח אֶת־כָּל־הַחֵלֶב אֲשֶׁר עַל־הַקֶּרֶב וְאֵת יֹתֶרֶת הַכָּבֵד וְאֶת־שְׁתֵּי הַכְּלָיֹת וְאֶת־חֶלְבְּהֶן וַיַּקְטֵר מֹשֶׁה הַמִּזְבֵּחָה׃
וְאֶת־הַפָּר וְאֶת־עֹרוֹ וְאֶת־בְּשָׂרוֹ וְאֶת־פִּרְשׁוֹ שָׂרַף בָּאֵשׁ מִחוּץ לַמַּחֲנֶה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּקְרֵב אֵת אֵיל הָעֹלָה וַיִּסְמְכוּ אַהֲרֹן וּבָנָיו אֶת־יְדֵיהֶם עַל־רֹאשׁ הָאָיִל׃
וַיִּשְׁחָט וַיִּזְרֹק מֹשֶׁה אֶת־הַדָּם עַל־הַמִּזְבֵּחַ סָבִיב׃
וְאֶת־הָאַיִל נִתַּח לִנְתָחָיו וַיַּקְטֵר מֹשֶׁה אֶת־הָרֹאשׁ וְאֶת־הַנְּתָחִים וְאֶת־הַפָּדֶר׃
וְאֶת־הַקֶּרֶב וְאֶת־הַכְּרָעַיִם רָחַץ בַּמָּיִם וַיַּקְטֵר מֹשֶׁה אֶת־כָּל־הָאַיִל הַמִּזְבֵּחָה עֹלָה הוּא לְרֵיחַ־נִיחֹחַ אִשֶּׁה הוּא לַיהוָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּקְרֵב אֶת־הָאַיִל הַשֵּׁנִי אֵיל הַמִּלֻּאִים וַיִּסְמְכוּ אַהֲרֹן וּבָנָיו אֶת־יְדֵיהֶם עַל־רֹאשׁ הָאָיִל׃
וַיִּשְׁחָט וַיִּקַּח מֹשֶׁה מִדָּמוֹ וַיִּתֵּן עַל־תְּנוּךְ אֹזֶן־אַהֲרֹן הַיְמָנִית וְעַל־בֹּהֶן יָדוֹ הַיְמָנִית וְעַל־בֹּהֶן רַגְלוֹ הַיְמָנִית׃
וַיַּקְרֵב אֶת־בְּנֵי אַהֲרֹן וַיִּתֵּן מֹשֶׁה מִן־הַדָּם עַל־תְּנוּךְ אָזְנָם הַיְמָנִית וְעַל־בֹּהֶן יָדָם הַיְמָנִית וְעַל־בֹּהֶן רַגְלָם הַיְמָנִית וַיִּזְרֹק מֹשֶׁה אֶת־הַדָּם עַל־הַמִּזְבֵּחַ סָבִיב׃
וַיִּקַּח אֶת־הַחֵלֶב וְאֶת־הָאַלְיָה וְאֶת־כָּל־הַחֵלֶב אֲשֶׁר עַל־הַקֶּרֶב וְאֵת יֹתֶרֶת הַכָּבֵד וְאֶת־שְׁתֵּי הַכְּלָיֹת וְאֶת־חֶלְבְּהֶן וְאֵת שׁוֹק הַיָּמִין׃
וּמִסַּל הַמַּצּוֹת אֲשֶׁר לִפְנֵי יְהוָה לָקַח חַלַּת מַצָּה אַחַת וְחַלַּת לֶחֶם שֶׁמֶן אַחַת וְרָקִיק אֶחָד וַיָּשֶׂם עַל־הַחֲלָבִים וְעַל שׁוֹק הַיָּמִין׃
וַיִּתֵּן אֶת־הַכֹּל עַל כַּפֵּי אַהֲרֹן וְעַל כַּפֵּי בָנָיו וַיָּנֶף אֹתָם תְּנוּפָה לִפְנֵי יְהוָה׃
וַיִּקַּח מֹשֶׁה אֹתָם מֵעַל כַּפֵּיהֶם וַיַּקְטֵר הַמִּזְבֵּחָה עַל־הָעֹלָה מִלֻּאִים הֵם לְרֵיחַ נִיחֹחַ אִשֶּׁה הוּא לַיהוָה׃
וַיִּקַּח מֹשֶׁה אֶת־הֶחָזֶה וַיְנִיפֵהוּ תְנוּפָה לִפְנֵי יְהוָה מֵאֵיל הַמִּלֻּאִים לְמֹשֶׁה הָיָה לְמָנָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיִּקַּח מֹשֶׁה מִשֶּׁמֶן הַמִּשְׁחָה וּמִן־הַדָּם אֲשֶׁר עַל־הַמִּזְבֵּחַ וַיַּז עַל־אַהֲרֹן עַל־בְּגָדָיו וְעַל־בָּנָיו וְעַל־בִּגְדֵי בָנָיו אִתּוֹ וַיְקַדֵּשׁ אֶת־אַהֲרֹן אֶת־בְּגָדָיו וְאֶת־בָּנָיו וְאֶת־בִּגְדֵי בָנָיו אִתּוֹ׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן וְאֶל־בָּנָיו בַּשְּׁלוּ אֶת־הַבָּשָׂר פֶּתַח אֹהֶל מוֹעֵד וְשָׁם תֹּאכְלוּ אֹתוֹ וְאֶת־הַלֶּחֶם אֲשֶׁר בְּסַל הַמִּלֻּאִים כַּאֲשֶׁר צִוֵּיתִי לֵאמֹר אַהֲרֹן וּבָנָיו יֹאכְלֻהוּ׃
וְהַנּוֹתָר בַּבָּשָׂר וּבַלָּחֶם בָּאֵשׁ תִּשְׂרֹפוּ׃
וּמִפֶּתַח אֹהֶל מוֹעֵד לֹא תֵצְאוּ שִׁבְעַת יָמִים עַד יוֹם מְלֹאת יְמֵי מִלֻּאֵיכֶם כִּי שִׁבְעַת יָמִים יְמַלֵּא אֶת־יֶדְכֶם׃
כַּאֲשֶׁר עָשָׂה בַּיּוֹם הַזֶּה צִוָּה יְהוָה לַעֲשֹׂת לְכַפֵּר עֲלֵיכֶם׃
וּפֶתַח אֹהֶל מוֹעֵד תֵּשְׁבוּ יוֹמָם וָלַיְלָה שִׁבְעַת יָמִים וּשְׁמַרְתֶּם אֶת־מִשְׁמֶרֶת יְהוָה וְלֹא תָמוּתוּ כִּי־כֵן צֻוֵּיתִי׃
וַיַּעַשׂ אַהֲרֹן וּבָנָיו אֵת כָּל־הַדְּבָרִים אֲשֶׁר־צִוָּה יְהוָה בְּיַד־מֹשֶׁה׃

Chapter 9

וַיְהִי בַּיּוֹם הַשְּׁמִינִי קָרָא מֹשֶׁה לְאַהֲרֹן וּלְבָנָיו וּלְזִקְנֵי יִשְׂרָאֵל׃
וַיֹּאמֶר אֶל־אַהֲרֹן קַח־לְךָ עֵגֶל בֶּן־בָּקָר לְחַטָּאת וְאַיִל לְעֹלָה תְּמִימִם וְהַקְרֵב לִפְנֵי יְהוָה׃
וְאֶל־בְּנֵי יִשְׂרָאֵל תְּדַבֵּר לֵאמֹר קְחוּ שְׂעִיר־עִזִּים לְחַטָּאת וְעֵגֶל וָכֶבֶשׂ בְּנֵי־שָׁנָה תְּמִימִם לְעֹלָה׃
וְשׁוֹר וָאַיִל לִשְׁלָמִים לִזְבֹּחַ לִפְנֵי יְהוָה וּמִנְחָה בְּלוּלָה בַשָּׁמֶן כִּי הַיּוֹם יְהוָה נִרְאָה אֲלֵיכֶם׃
וַיִּקְחוּ אֵת אֲשֶׁר צִוָּה מֹשֶׁה אֶל־פְּנֵי אֹהֶל מוֹעֵד וַיִּקְרְבוּ כָּל־הָעֵדָה וַיַּעַמְדוּ לִפְנֵי יְהוָה׃
וַיֹּאמֶר מֹשֶׁה זֶה הַדָּבָר אֲשֶׁר־צִוָּה יְהוָה תַּעֲשׂוּ וְיֵרָא אֲלֵיכֶם כְּבוֹד יְהוָה׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן קְרַב אֶל־הַמִּזְבֵּחַ וַעֲשֵׂה אֶת־חַטָּאתְךָ וְאֶת־עֹלָתֶךָ וְכַפֵּר בַּעַדְךָ וּבְעַד הָעָם וַעֲשֵׂה אֶת־קָרְבַּן הָעָם וְכַפֵּר בַּעֲדָם כַּאֲשֶׁר צִוָּה יְהוָה׃
וַיִּקְרַב אַהֲרֹן אֶל־הַמִּזְבֵּחַ וַיִּשְׁחַט אֶת־עֵגֶל הַחַטָּאת אֲשֶׁר־לוֹ׃
וַיַּקְרִבוּ בְּנֵי אַהֲרֹן אֶת־הַדָּם אֵלָיו וַיִּטְבֹּל אֶצְבָּעוֹ בַּדָּם וַיִּתֵּן עַל־קַרְנוֹת הַמִּזְבֵּחַ וְאֶת־הַדָּם יָצַק אֶל־יְסוֹד הַמִּזְבֵּחַ׃
וְאֶת־הַחֵלֶב וְאֶת־הַכְּלָיֹת וְאֶת־הַיֹּתֶרֶת מִן־הַכָּבֵד מִן־הַחַטָּאת הִקְטִיר הַמִּזְבֵּחָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וְאֶת־הַבָּשָׂר וְאֶת־הָעוֹר שָׂרַף בָּאֵשׁ מִחוּץ לַמַּחֲנֶה׃
וַיִּשְׁחַט אֶת־הָעֹלָה וַיַּמְצִאוּ בְּנֵי אַהֲרֹן אֵלָיו אֶת־הַדָּם וַיִּזְרְקֵהוּ עַל־הַמִּזְבֵּחַ סָבִיב׃
וְאֶת־הָעֹלָה הִמְצִיאוּ אֵלָיו לִנְתָחֶיהָ וְאֶת־הָרֹאשׁ וַיַּקְטֵר עַל־הַמִּזְבֵּחַ׃
וַיִּרְחַץ אֶת־הַקֶּרֶב וְאֶת־הַכְּרָעָיִם וַיַּקְטֵר עַל־הָעֹלָה הַמִּזְבֵּחָה׃
וַיַּקְרֵב אֵת קָרְבַּן הָעָם וַיִּקַּח אֶת־שְׂעִיר הַחַטָּאת אֲשֶׁר לָעָם וַיִּשְׁחָטֵהוּ וַיְחַטְּאֵהוּ כָּרִאשׁוֹן׃
וַיַּקְרֵב אֶת־הָעֹלָה וַיַּעֲשֶׂהָ כַּמִּשְׁפָּט׃
וַיַּקְרֵב אֶת־הַמִּנְחָה וַיְמַלֵּא כַפּוֹ מִמֶּנָּה וַיַּקְטֵר עַל־הַמִּזְבֵּחַ מִלְּבַד עֹלַת הַבֹּקֶר׃
וַיִּשְׁחַט אֶת־הַשּׁוֹר וְאֶת־הָאַיִל זֶבַח הַשְּׁלָמִים אֲשֶׁר לָעָם וַיַּמְצִאוּ בְּנֵי אַהֲרֹן אֶת־הַדָּם אֵלָיו וַיִּזְרְקֵהוּ עַל־הַמִּזְבֵּחַ סָבִיב׃
וְאֶת־הַחֲלָבִים מִן־הַשּׁוֹר וּמִן־הָאַיִל הָאַלְיָה וְהַמְכַסֶּה וְהַכְּלָיֹת וְיֹתֶרֶת הַכָּבֵד׃
וַיָּשִׂימוּ אֶת־הַחֲלָבִים עַל־הֶחָזוֹת וַיַּקְטֵר הַחֲלָבִים הַמִּזְבֵּחָה׃
וְאֵת הֶחָזוֹת וְאֵת שׁוֹק הַיָּמִין הֵנִיף אַהֲרֹן תְּנוּפָה לִפְנֵי יְהוָה כַּאֲשֶׁר צִוָּה מֹשֶׁה׃
וַיִּשָּׂא אַהֲרֹן אֶת־ידו [יָדָיו] אֶל־הָעָם וַיְבָרְכֵם וַיֵּרֶד מֵעֲשֹׂת הַחַטָּאת וְהָעֹלָה וְהַשְּׁלָמִים׃
וַיָּבֹא מֹשֶׁה וְאַהֲרֹן אֶל־אֹהֶל מוֹעֵד וַיֵּצְאוּ וַיְבָרֲכוּ אֶת־הָעָם וַיֵּרָא כְבוֹד־יְהוָה אֶל־כָּל־הָעָם׃
וַתֵּצֵא אֵשׁ מִלִּפְנֵי יְהוָה וַתֹּאכַל עַל־הַמִּזְבֵּחַ אֶת־הָעֹלָה וְאֶת־הַחֲלָבִים וַיַּרְא כָּל־הָעָם וַיָּרֹנּוּ וַיִּפְּלוּ עַל־פְּנֵיהֶם׃

Chapter 10

וַיִּקְחוּ בְנֵי־אַהֲרֹן נָדָב וַאֲבִיהוּא אִישׁ מַחְתָּתוֹ וַיִּתְּנוּ בָהֵן אֵשׁ וַיָּשִׂימוּ עָלֶיהָ קְטֹרֶת וַיַּקְרִבוּ לִפְנֵי יְהוָה אֵשׁ זָרָה אֲשֶׁר לֹא צִוָּה אֹתָם׃
וַתֵּצֵא אֵשׁ מִלִּפְנֵי יְהוָה וַתֹּאכַל אוֹתָם וַיָּמֻתוּ לִפְנֵי יְהוָה׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן הוּא אֲשֶׁר־דִּבֶּר יְהוָה לֵאמֹר בִּקְרֹבַי אֶקָּדֵשׁ וְעַל־פְּנֵי כָל־הָעָם אֶכָּבֵד וַיִּדֹּם אַהֲרֹן׃
וַיִּקְרָא מֹשֶׁה אֶל־מִישָׁאֵל וְאֶל אֶלְצָפָן בְּנֵי עֻזִּיאֵל דֹּד אַהֲרֹן וַיֹּאמֶר אֲלֵהֶם קִרְבוּ שְׂאוּ אֶת־אֲחֵיכֶם מֵאֵת פְּנֵי־הַקֹּדֶשׁ אֶל־מִחוּץ לַמַּחֲנֶה׃
וַיִּקְרְבוּ וַיִּשָּׂאֻם בְּכֻתֳּנֹתָם אֶל־מִחוּץ לַמַּחֲנֶה כַּאֲשֶׁר דִּבֶּר מֹשֶׁה׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן וּלְאֶלְעָזָר וּלְאִיתָמָר בָּנָיו רָאשֵׁיכֶם אַל־תִּפְרָעוּ וּבִגְדֵיכֶם לֹא־תִפְרֹמוּ וְלֹא תָמֻתוּ וְעַל כָּל־הָעֵדָה יִקְצֹף וַאֲחֵיכֶם כָּל־בֵּית יִשְׂרָאֵל יִבְכּוּ אֶת־הַשְּׂרֵפָה אֲשֶׁר שָׂרַף יְהוָה׃
וּמִפֶּתַח אֹהֶל מוֹעֵד לֹא תֵצְאוּ פֶּן־תָּמֻתוּ כִּי־שֶׁמֶן מִשְׁחַת יְהוָה עֲלֵיכֶם וַיַּעֲשׂוּ כִּדְבַר מֹשֶׁה׃
וַיְדַבֵּר יְהוָה אֶל־אַהֲרֹן לֵאמֹר׃
יַיִן וְשֵׁכָר אַל־תֵּשְׁתְּ אַתָּה וּבָנֶיךָ אִתָּךְ בְּבֹאֲכֶם אֶל־אֹהֶל מוֹעֵד וְלֹא תָמֻתוּ חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם׃
וּלֲהַבְדִּיל בֵּין הַקֹּדֶשׁ וּבֵין הַחֹל וּבֵין הַטָּמֵא וּבֵין הַטָּהוֹר׃
וּלְהוֹרֹת אֶת־בְּנֵי יִשְׂרָאֵל אֵת כָּל־הַחֻקִּים אֲשֶׁר דִּבֶּר יְהוָה אֲלֵיהֶם בְּיַד־מֹשֶׁה׃
וַיְדַבֵּר מֹשֶׁה אֶל־אַהֲרֹן וְאֶל אֶלְעָזָר וְאֶל־אִיתָמָר בָּנָיו הַנּוֹתָרִים קְחוּ אֶת־הַמִּנְחָה הַנּוֹתֶרֶת מֵאִשֵּׁי יְהוָה וְאִכְלוּהָ מַצּוֹת אֵצֶל הַמִּזְבֵּחַ כִּי קֹדֶשׁ קָדָשִׁים הִוא׃
וַאֲכַלְתֶּם אֹתָהּ בְּמָקוֹם קָדֹשׁ כִּי חָקְךָ וְחָק־בָּנֶיךָ הִוא מֵאִשֵּׁי יְהוָה כִּי־כֵן צֻוֵּיתִי׃
וְאֵת חֲזֵה הַתְּנוּפָה וְאֵת שׁוֹק הַתְּרוּמָה תֹּאכְלוּ בְּמָקוֹם טָהוֹר אַתָּה וּבָנֶיךָ וּבְנֹתֶיךָ אִתָּךְ כִּי־חָקְךָ וְחָק־בָּנֶיךָ נִתְּנוּ מִזִּבְחֵי שַׁלְמֵי בְּנֵי יִשְׂרָאֵל׃
שׁוֹק הַתְּרוּמָה וַחֲזֵה הַתְּנוּפָה עַל אִשֵּׁי הַחֲלָבִים יָבִיאוּ לְהָנִיף תְּנוּפָה לִפְנֵי יְהוָה וְהָיָה לְךָ וּלְבָנֶיךָ אִתְּךָ לְחָק־עוֹלָם כַּאֲשֶׁר צִוָּה יְהוָה׃
וְאֵת שְׂעִיר הַחַטָּאת דָּרֹשׁ דָּרַשׁ מֹשֶׁה וְהִנֵּה שֹׂרָף וַיִּקְצֹף עַל־אֶלְעָזָר וְעַל־אִיתָמָר בְּנֵי אַהֲרֹן הַנּוֹתָרִם לֵאמֹר׃
מַדּוּעַ לֹא־אֲכַלְתֶּם אֶת־הַחַטָּאת בִּמְקוֹם הַקֹּדֶשׁ כִּי קֹדֶשׁ קָדָשִׁים הִוא וְאֹתָהּ נָתַן לָכֶם לָשֵׂאת אֶת־עֲוֺן הָעֵדָה לְכַפֵּר עֲלֵיהֶם לִפְנֵי יְהוָה׃
הֵן לֹא־הוּבָא אֶת־דָּמָהּ אֶל־הַקֹּדֶשׁ פְּנִימָה אָכוֹל תֹּאכְלוּ אֹתָהּ בַּקֹּדֶשׁ כַּאֲשֶׁר צִוֵּיתִי׃
וַיְדַבֵּר אַהֲרֹן אֶל־מֹשֶׁה הֵן הַיּוֹם הִקְרִיבוּ אֶת־חַטָּאתָם וְאֶת־עֹלָתָם לִפְנֵי יְהוָה וַתִּקְרֶאנָה אֹתִי כָּאֵלֶּה וְאָכַלְתִּי חַטָּאת הַיּוֹם הַיִּיטַב בְּעֵינֵי יְהוָה׃
וַיִּשְׁמַע מֹשֶׁה וַיִּיטַב בְּעֵינָיו׃

Chapter 11

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר אֲלֵהֶם׃
דַּבְּרוּ אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר זֹאת הַחַיָּה אֲשֶׁר תֹּאכְלוּ מִכָּל־הַבְּהֵמָה אֲשֶׁר עַל־הָאָרֶץ׃
כֹּל מַפְרֶסֶת פַּרְסָה וְשֹׁסַעַת שֶׁסַע פְּרָסֹת מַעֲלַת גֵּרָה בַּבְּהֵמָה אֹתָהּ תֹּאכֵלוּ׃
אַךְ אֶת־זֶה לֹא תֹאכְלוּ מִמַּעֲלֵי הַגֵּרָה וּמִמַּפְרִיסֵי הַפַּרְסָה אֶת־הַגָּמָל כִּי־מַעֲלֵה גֵרָה הוּא וּפַרְסָה אֵינֶנּוּ מַפְרִיס טָמֵא הוּא לָכֶם׃
וְאֶת־הַשָּׁפָן כִּי־מַעֲלֵה גֵרָה הוּא וּפַרְסָה לֹא יַפְרִיס טָמֵא הוּא לָכֶם׃
וְאֶת־הָאַרְנֶבֶת כִּי־מַעֲלַת גֵּרָה הִוא וּפַרְסָה לֹא הִפְרִיסָה טְמֵאָה הִוא לָכֶם׃
וְאֶת־הַחֲזִיר כִּי־מַפְרִיס פַּרְסָה הוּא וְשֹׁסַע שֶׁסַע פַּרְסָה וְהוּא גֵּרָה לֹא־יִגָּר טָמֵא הוּא לָכֶם׃
מִבְּשָׂרָם לֹא תֹאכֵלוּ וּבְנִבְלָתָם לֹא תִגָּעוּ טְמֵאִים הֵם לָכֶם׃
אֶת־זֶה תֹּאכְלוּ מִכֹּל אֲשֶׁר בַּמָּיִם כֹּל אֲשֶׁר־לוֹ סְנַפִּיר וְקַשְׂקֶשֶׂת בַּמַּיִם בַּיַּמִּים וּבַנְּחָלִים אֹתָם תֹּאכֵלוּ׃
וְכֹל אֲשֶׁר אֵין־לוֹ סְנַפִּיר וְקַשְׂקֶשֶׂת בַּיַּמִּים וּבַנְּחָלִים מִכֹּל שֶׁרֶץ הַמַּיִם וּמִכֹּל נֶפֶשׁ הַחַיָּה אֲשֶׁר בַּמָּיִם שֶׁקֶץ הֵם לָכֶם׃
וְשֶׁקֶץ יִהְיוּ לָכֶם מִבְּשָׂרָם לֹא תֹאכֵלוּ וְאֶת־נִבְלָתָם תְּשַׁקֵּצוּ׃
כֹּל אֲשֶׁר אֵין־לוֹ סְנַפִּיר וְקַשְׂקֶשֶׂת בַּמָּיִם שֶׁקֶץ הוּא לָכֶם׃
וְאֶת־אֵלֶּה תְּשַׁקְּצוּ מִן־הָעוֹף לֹא יֵאָכְלוּ שֶׁקֶץ הֵם אֶת־הַנֶּשֶׁר וְאֶת־הַפֶּרֶס וְאֵת הָעָזְנִיָּה׃
וְאֶת־הַדָּאָה וְאֶת־הָאַיָּה לְמִינָהּ׃
אֵת כָּל־עֹרֵב לְמִינוֹ׃
וְאֵת בַּת הַיַּעֲנָה וְאֶת־הַתַּחְמָס וְאֶת־הַשָּׁחַף וְאֶת־הַנֵּץ לְמִינֵהוּ׃
וְאֶת־הַכּוֹס וְאֶת־הַשָּׁלָךְ וְאֶת־הַיַּנְשׁוּף׃
וְאֶת־הַתִּנְשֶׁמֶת וְאֶת־הַקָּאָת וְאֶת־הָרָחָם׃
וְאֵת הַחֲסִידָה הָאֲנָפָה לְמִינָהּ וְאֶת־הַדּוּכִיפַת וְאֶת־הָעֲטַלֵּף׃
כֹּל שֶׁרֶץ הָעוֹף הַהֹלֵךְ עַל־אַרְבַּע שֶׁקֶץ הוּא לָכֶם׃
אַךְ אֶת־זֶה תֹּאכְלוּ מִכֹּל שֶׁרֶץ הָעוֹף הַהֹלֵךְ עַל־אַרְבַּע אֲשֶׁר־לא [לוֹ] כְרָעַיִם מִמַּעַל לְרַגְלָיו לְנַתֵּר בָּהֵן עַל־הָאָרֶץ׃
אֶת־אֵלֶּה מֵהֶם תֹּאכֵלוּ אֶת־הָאַרְבֶּה לְמִינוֹ וְאֶת־הַסָּלְעָם לְמִינֵהוּ וְאֶת־הַחַרְגֹּל לְמִינֵהוּ וְאֶת־הֶחָגָב לְמִינֵהוּ׃
וְכֹל שֶׁרֶץ הָעוֹף אֲשֶׁר־לוֹ אַרְבַּע רַגְלָיִם שֶׁקֶץ הוּא לָכֶם׃
וּלְאֵלֶּה תִּטַּמָּאוּ כָּל־הַנֹּגֵעַ בְּנִבְלָתָם יִטְמָא עַד־הָעָרֶב׃
וְכָל־הַנֹּשֵׂא מִנִּבְלָתָם יְכַבֵּס בְּגָדָיו וְטָמֵא עַד־הָעָרֶב׃
לְכָל־הַבְּהֵמָה אֲשֶׁר הִוא מַפְרֶסֶת פַּרְסָה וְשֶׁסַע אֵינֶנָּה שֹׁסַעַת וְגֵרָה אֵינֶנָּה מַעֲלָה טְמֵאִים הֵם לָכֶם כָּל־הַנֹּגֵעַ בָּהֶם יִטְמָא׃
וְכֹל הוֹלֵךְ עַל־כַּפָּיו בְּכָל־הַחַיָּה הַהֹלֶכֶת עַל־אַרְבַּע טְמֵאִים הֵם לָכֶם כָּל־הַנֹּגֵעַ בְּנִבְלָתָם יִטְמָא עַד־הָעָרֶב׃
וְהַנֹּשֵׂא אֶת־נִבְלָתָם יְכַבֵּס בְּגָדָיו וְטָמֵא עַד־הָעָרֶב טְמֵאִים הֵמָּה לָכֶם׃
וְזֶה לָכֶם הַטָּמֵא בַּשֶּׁרֶץ הַשֹּׁרֵץ עַל־הָאָרֶץ הַחֹלֶד וְהָעַכְבָּר וְהַצָּב לְמִינֵהוּ׃
וְהָאֲנָקָה וְהַכֹּחַ וְהַלְּטָאָה וְהַחֹמֶט וְהַתִּנְשָׁמֶת׃
אֵלֶּה הַטְּמֵאִים לָכֶם בְּכָל־הַשָּׁרֶץ כָּל־הַנֹּגֵעַ בָּהֶם בְּמֹתָם יִטְמָא עַד־הָעָרֶב׃
וְכֹל אֲשֶׁר־יִפֹּל־עָלָיו מֵהֶם בְּמֹתָם יִטְמָא מִכָּל־כְּלִי־עֵץ אוֹ בֶגֶד אוֹ־עוֹר אוֹ שָׂק כָּל־כְּלִי אֲשֶׁר־יֵעָשֶׂה מְלָאכָה בָּהֶם בַּמַּיִם יוּבָא וְטָמֵא עַד־הָעֶרֶב וְטָהֵר׃
וְכָל־כְּלִי־חֶרֶשׂ אֲשֶׁר־יִפֹּל מֵהֶם אֶל־תּוֹכוֹ כֹּל אֲשֶׁר בְּתוֹכוֹ יִטְמָא וְאֹתוֹ תִשְׁבֹּרוּ׃
מִכָּל־הָאֹכֶל אֲשֶׁר יֵאָכֵל אֲשֶׁר יָבוֹא עָלָיו מַיִם יִטְמָא וְכָל־מַשְׁקֶה אֲשֶׁר יִשָּׁתֶה בְּכָל־כְּלִי יִטְמָא׃
וְכֹל אֲשֶׁר־יִפֹּל מִנִּבְלָתָם עָלָיו יִטְמָא תַּנּוּר וְכִירַיִם יֻתָּץ טְמֵאִים הֵם וּטְמֵאִים יִהְיוּ לָכֶם׃
אַךְ מַעְיָן וּבוֹר מִקְוֵה־מַיִם יִהְיֶה טָהוֹר וְנֹגֵעַ בְּנִבְלָתָם יִטְמָא׃
וְכִי יִפֹּל מִנִּבְלָתָם עַל־כָּל־זֶרַע זֵרוּעַ אֲשֶׁר יִזָּרֵעַ טָהוֹר הוּא׃
וְכִי יֻתַּן־מַיִם עַל־זֶרַע וְנָפַל מִנִּבְלָתָם עָלָיו טָמֵא הוּא לָכֶם׃
וְכִי יָמוּת מִן־הַבְּהֵמָה אֲשֶׁר־הִיא לָכֶם לְאָכְלָה הַנֹּגֵעַ בְּנִבְלָתָהּ יִטְמָא עַד־הָעָרֶב׃
וְהָאֹכֵל מִנִּבְלָתָהּ יְכַבֵּס בְּגָדָיו וְטָמֵא עַד־הָעָרֶב וְהַנֹּשֵׂא אֶת־נִבְלָתָהּ יְכַבֵּס בְּגָדָיו וְטָמֵא עַד־הָעָרֶב׃
וְכָל־הַשֶּׁרֶץ הַשֹּׁרֵץ עַל־הָאָרֶץ שֶׁקֶץ הוּא לֹא יֵאָכֵל׃
כֹּל הוֹלֵךְ עַל־גָּחוֹן וְכֹל הוֹלֵךְ עַל־אַרְבַּע עַד כָּל־מַרְבֵּה רַגְלַיִם לְכָל־הַשֶּׁרֶץ הַשֹּׁרֵץ עַל־הָאָרֶץ לֹא תֹאכְלוּם כִּי־שֶׁקֶץ הֵם׃
אַל־תְּשַׁקְּצוּ אֶת־נַפְשֹׁתֵיכֶם בְּכָל־הַשֶּׁרֶץ הַשֹּׁרֵץ וְלֹא תִטַּמְּאוּ בָּהֶם וְנִטְמֵתֶם בָּם׃
כִּי אֲנִי יְהוָה אֱלֹהֵיכֶם וְהִתְקַדִּשְׁתֶּם וִהְיִיתֶם קְדֹשִׁים כִּי קָדוֹשׁ אָנִי וְלֹא תְטַמְּאוּ אֶת־נַפְשֹׁתֵיכֶם בְּכָל־הַשֶּׁרֶץ הָרֹמֵשׂ עַל־הָאָרֶץ׃
כִּי אֲנִי יְהוָה הַמַּעֲלֶה אֶתְכֶם מֵאֶרֶץ מִצְרַיִם לִהְיֹת לָכֶם לֵאלֹהִים וִהְיִיתֶם קְדֹשִׁים כִּי קָדוֹשׁ אָנִי׃
זֹאת תּוֹרַת הַבְּהֵמָה וְהָעוֹף וְכֹל נֶפֶשׁ הַחַיָּה הָרֹמֶשֶׂת בַּמָּיִם וּלְכָל־נֶפֶשׁ הַשֹּׁרֶצֶת עַל־הָאָרֶץ׃
לְהַבְדִּיל בֵּין הַטָּמֵא וּבֵין הַטָּהֹר וּבֵין הַחַיָּה הַנֶּאֱכֶלֶת וּבֵין הַחַיָּה אֲשֶׁר לֹא תֵאָכֵל׃

Chapter 12

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר אִשָּׁה כִּי תַזְרִיעַ וְיָלְדָה זָכָר וְטָמְאָה שִׁבְעַת יָמִים כִּימֵי נִדַּת דְּוֺתָהּ תִּטְמָא׃
וּבַיּוֹם הַשְּׁמִינִי יִמּוֹל בְּשַׂר עָרְלָתוֹ׃
וּשְׁלֹשִׁים יוֹם וּשְׁלֹשֶׁת יָמִים תֵּשֵׁב בִּדְמֵי טָהֳרָה בְּכָל־קֹדֶשׁ לֹא־תִגָּע וְאֶל־הַמִּקְדָּשׁ לֹא תָבֹא עַד־מְלֹאת יְמֵי טָהֳרָהּ׃
וְאִם־נְקֵבָה תֵלֵד וְטָמְאָה שְׁבֻעַיִם כְּנִדָּתָהּ וְשִׁשִּׁים יוֹם וְשֵׁשֶׁת יָמִים תֵּשֵׁב עַל־דְּמֵי טָהֳרָה׃
וּבִמְלֹאת יְמֵי טָהֳרָהּ לְבֵן אוֹ לְבַת תָּבִיא כֶּבֶשׂ בֶּן־שְׁנָתוֹ לְעֹלָה וּבֶן־יוֹנָה אוֹ־תֹר לְחַטָּאת אֶל־פֶּתַח אֹהֶל־מוֹעֵד אֶל־הַכֹּהֵן׃
וְהִקְרִיבוֹ לִפְנֵי יְהוָה וְכִפֶּר עָלֶיהָ וְטָהֲרָה מִמְּקֹר דָּמֶיהָ זֹאת תּוֹרַת הַיֹּלֶדֶת לַזָּכָר אוֹ לַנְּקֵבָה׃
וְאִם־לֹא תִמְצָא יָדָהּ דֵּי שֶׂה וְלָקְחָה שְׁתֵּי־תֹרִים אוֹ שְׁנֵי בְּנֵי יוֹנָה אֶחָד לְעֹלָה וְאֶחָד לְחַטָּאת וְכִפֶּר עָלֶיהָ הַכֹּהֵן וְטָהֵרָה׃

Chapter 13

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
אָדָם כִּי־יִהְיֶה בְעוֹר־בְּשָׂרוֹ שְׂאֵת אוֹ־סַפַּחַת אוֹ בַהֶרֶת וְהָיָה בְעוֹר־בְּשָׂרוֹ לְנֶגַע צָרָעַת וְהוּבָא אֶל־אַהֲרֹן הַכֹּהֵן אוֹ אֶל־אַחַד מִבָּנָיו הַכֹּהֲנִים׃
וְרָאָה הַכֹּהֵן אֶת־הַנֶּגַע בְּעוֹר־הַבָּשָׂר וְשֵׂעָר בַּנֶּגַע הָפַךְ לָבָן וּמַרְאֵה הַנֶּגַע עָמֹק מֵעוֹר בְּשָׂרוֹ נֶגַע צָרַעַת הוּא וְרָאָהוּ הַכֹּהֵן וְטִמֵּא אֹתוֹ׃
וְאִם־בַּהֶרֶת לְבָנָה הִוא בְּעוֹר בְּשָׂרוֹ וְעָמֹק אֵין־מַרְאֶהָ מִן־הָעוֹר וּשְׂעָרָה לֹא־הָפַךְ לָבָן וְהִסְגִּיר הַכֹּהֵן אֶת־הַנֶּגַע שִׁבְעַת יָמִים׃
וְרָאָהוּ הַכֹּהֵן בַּיּוֹם הַשְּׁבִיעִי וְהִנֵּה הַנֶּגַע עָמַד בְּעֵינָיו לֹא־פָשָׂה הַנֶּגַע בָּעוֹר וְהִסְגִּירוֹ הַכֹּהֵן שִׁבְעַת יָמִים שֵׁנִית׃
וְרָאָה הַכֹּהֵן אֹתוֹ בַּיּוֹם הַשְּׁבִיעִי שֵׁנִית וְהִנֵּה כֵּהָה הַנֶּגַע וְלֹא־פָשָׂה הַנֶּגַע בָּעוֹר וְטִהֲרוֹ הַכֹּהֵן מִסְפַּחַת הִיא וְכִבֶּס בְּגָדָיו וְטָהֵר׃
וְאִם־פָּשֹׂה תִפְשֶׂה הַמִּסְפַּחַת בָּעוֹר אַחֲרֵי הֵרָאֹתוֹ אֶל־הַכֹּהֵן לְטָהֳרָתוֹ וְנִרְאָה שֵׁנִית אֶל־הַכֹּהֵן׃
וְרָאָה הַכֹּהֵן וְהִנֵּה פָּשְׂתָה הַמִּסְפַּחַת בָּעוֹר וְטִמְּאוֹ הַכֹּהֵן צָרַעַת הִוא׃
נֶגַע צָרַעַת כִּי תִהְיֶה בְּאָדָם וְהוּבָא אֶל־הַכֹּהֵן׃
וְרָאָה הַכֹּהֵן וְהִנֵּה שְׂאֵת־לְבָנָה בָּעוֹר וְהִיא הָפְכָה שֵׂעָר לָבָן וּמִחְיַת בָּשָׂר חַי בַּשְׂאֵת׃
צָרַעַת נוֹשֶׁנֶת הִוא בְּעוֹר בְּשָׂרוֹ וְטִמְּאוֹ הַכֹּהֵן לֹא יַסְגִּרֶנּוּ כִּי טָמֵא הוּא׃
וְאִם־פָּרוֹחַ תִּפְרַח הַצָּרַעַת בָּעוֹר וְכִסְּתָה הַצָּרַעַת אֵת כָּל־עוֹר הַנֶּגַע מֵרֹאשׁוֹ וְעַד־רַגְלָיו לְכָל־מַרְאֵה עֵינֵי הַכֹּהֵן׃
וְרָאָה הַכֹּהֵן וְהִנֵּה כִסְּתָה הַצָּרַעַת אֶת־כָּל־בְּשָׂרוֹ וְטִהַר אֶת־הַנָּגַע כֻּלּוֹ הָפַךְ לָבָן טָהוֹר הוּא׃
וּבְיוֹם הֵרָאוֹת בּוֹ בָּשָׂר חַי יִטְמָא׃
וְרָאָה הַכֹּהֵן אֶת־הַבָּשָׂר הַחַי וְטִמְּאוֹ הַבָּשָׂר הַחַי טָמֵא הוּא צָרַעַת הוּא׃
אוֹ כִי יָשׁוּב הַבָּשָׂר הַחַי וְנֶהְפַּךְ לְלָבָן וּבָא אֶל־הַכֹּהֵן׃
וְרָאָהוּ הַכֹּהֵן וְהִנֵּה נֶהְפַּךְ הַנֶּגַע לְלָבָן וְטִהַר הַכֹּהֵן אֶת־הַנֶּגַע טָהוֹר הוּא׃
וּבָשָׂר כִּי־יִהְיֶה בוֹ־בְעֹרוֹ שְׁחִין וְנִרְפָּא׃
וְהָיָה בִּמְקוֹם הַשְּׁחִין שְׂאֵת לְבָנָה אוֹ בַהֶרֶת לְבָנָה אֲדַמְדָּמֶת וְנִרְאָה אֶל־הַכֹּהֵן׃
וְרָאָה הַכֹּהֵן וְהִנֵּה מַרְאֶהָ שָׁפָל מִן־הָעוֹר וּשְׂעָרָהּ הָפַךְ לָבָן וְטִמְּאוֹ הַכֹּהֵן נֶגַע־צָרַעַת הִוא בַּשְּׁחִין פָּרָחָה׃
וְאִם יִרְאֶנָּה הַכֹּהֵן וְהִנֵּה אֵין־בָּהּ שֵׂעָר לָבָן וּשְׁפָלָה אֵינֶנָּה מִן־הָעוֹר וְהִיא כֵהָה וְהִסְגִּירוֹ הַכֹּהֵן שִׁבְעַת יָמִים׃
וְאִם־פָּשֹׂה תִפְשֶׂה בָּעוֹר וְטִמֵּא הַכֹּהֵן אֹתוֹ נֶגַע הִוא׃
וְאִם־תַּחְתֶּיהָ תַּעֲמֹד הַבַּהֶרֶת לֹא פָשָׂתָה צָרֶבֶת הַשְּׁחִין הִוא וְטִהֲרוֹ הַכֹּהֵן׃
אוֹ בָשָׂר כִּי־יִהְיֶה בְעֹרוֹ מִכְוַת־אֵשׁ וְהָיְתָה מִחְיַת הַמִּכְוָה בַּהֶרֶת לְבָנָה אֲדַמְדֶּמֶת אוֹ לְבָנָה׃
וְרָאָה אֹתָהּ הַכֹּהֵן וְהִנֵּה נֶהְפַּךְ שֵׂעָר לָבָן בַּבַּהֶרֶת וּמַרְאֶהָ עָמֹק מִן־הָעוֹר צָרַעַת הִוא בַּמִּכְוָה פָּרָחָה וְטִמֵּא אֹתוֹ הַכֹּהֵן נֶגַע צָרַעַת הִוא׃
וְאִם יִרְאֶנָּה הַכֹּהֵן וְהִנֵּה אֵין־בַּבֶּהֶרֶת שֵׂעָר לָבָן וּשְׁפָלָה אֵינֶנָּה מִן־הָעוֹר וְהִוא כֵהָה וְהִסְגִּירוֹ הַכֹּהֵן שִׁבְעַת יָמִים׃
וְרָאָהוּ הַכֹּהֵן בַּיּוֹם הַשְּׁבִיעִי אִם־פָּשֹׂה תִפְשֶׂה בָּעוֹר וְטִמֵּא הַכֹּהֵן אֹתוֹ נֶגַע צָרַעַת הִוא׃
וְאִם־תַּחְתֶּיהָ תַעֲמֹד הַבַּהֶרֶת לֹא־פָשְׂתָה בָעוֹר וְהִוא כֵהָה שְׂאֵת הַמִּכְוָה הִוא וְטִהֲרוֹ הַכֹּהֵן כִּי־צָרֶבֶת הַמִּכְוָה הִוא׃
וְאִישׁ אוֹ אִשָּׁה כִּי־יִהְיֶה בוֹ נָגַע בְּרֹאשׁ אוֹ בְזָקָן׃
וְרָאָה הַכֹּהֵן אֶת־הַנֶּגַע וְהִנֵּה מַרְאֵהוּ עָמֹק מִן־הָעוֹר וּבוֹ שֵׂעָר צָהֹב דָּק וְטִמֵּא אֹתוֹ הַכֹּהֵן נֶתֶק הוּא צָרַעַת הָרֹאשׁ אוֹ הַזָּקָן הוּא׃
וְכִי־יִרְאֶה הַכֹּהֵן אֶת־נֶגַע הַנֶּתֶק וְהִנֵּה אֵין־מַרְאֵהוּ עָמֹק מִן־הָעוֹר וְשֵׂעָר שָׁחֹר אֵין בּוֹ וְהִסְגִּיר הַכֹּהֵן אֶת־נֶגַע הַנֶּתֶק שִׁבְעַת יָמִים׃
וְרָאָה הַכֹּהֵן אֶת־הַנֶּגַע בַּיּוֹם הַשְּׁבִיעִי וְהִנֵּה לֹא־פָשָׂה הַנֶּתֶק וְלֹא־הָיָה בוֹ שֵׂעָר צָהֹב וּמַרְאֵה הַנֶּתֶק אֵין עָמֹק מִן־הָעוֹר׃
וְהִתְגַּלָּח וְאֶת־הַנֶּתֶק לֹא יְגַלֵּחַ וְהִסְגִּיר הַכֹּהֵן אֶת־הַנֶּתֶק שִׁבְעַת יָמִים שֵׁנִית׃
וְרָאָה הַכֹּהֵן אֶת־הַנֶּתֶק בַּיּוֹם הַשְּׁבִיעִי וְהִנֵּה לֹא־פָשָׂה הַנֶּתֶק בָּעוֹר וּמַרְאֵהוּ אֵינֶנּוּ עָמֹק מִן־הָעוֹר וְטִהַר אֹתוֹ הַכֹּהֵן וְכִבֶּס בְּגָדָיו וְטָהֵר׃
וְאִם־פָּשֹׂה יִפְשֶׂה הַנֶּתֶק בָּעוֹר אַחֲרֵי טָהֳרָתוֹ׃
וְרָאָהוּ הַכֹּהֵן וְהִנֵּה פָּשָׂה הַנֶּתֶק בָּעוֹר לֹא־יְבַקֵּר הַכֹּהֵן לַשֵּׂעָר הַצָּהֹב טָמֵא הוּא׃
וְאִם־בְּעֵינָיו עָמַד הַנֶּתֶק וְשֵׂעָר שָׁחֹר צָמַח־בּוֹ נִרְפָּא הַנֶּתֶק טָהוֹר הוּא וְטִהֲרוֹ הַכֹּהֵן׃
וְאִישׁ אוֹ־אִשָּׁה כִּי־יִהְיֶה בְעוֹר־בְּשָׂרָם בֶּהָרֹת בֶּהָרֹת לְבָנֹת׃
וְרָאָה הַכֹּהֵן וְהִנֵּה בְעוֹר־בְּשָׂרָם בֶּהָרֹת כֵּהוֹת לְבָנֹת בֹּהַק הוּא פָּרַח בָּעוֹר טָהוֹר הוּא׃
וְאִישׁ כִּי יִמָּרֵט רֹאשׁוֹ קֵרֵחַ הוּא טָהוֹר הוּא׃
וְאִם מִפְּאַת פָּנָיו יִמָּרֵט רֹאשׁוֹ גִּבֵּחַ הוּא טָהוֹר הוּא׃
וְכִי־יִהְיֶה בַקָּרַחַת אוֹ בַגַּבַּחַת נֶגַע לָבָן אֲדַמְדָּם צָרַעַת פֹּרַחַת הִוא בְּקָרַחְתּוֹ אוֹ בְגַבַּחְתּוֹ׃
וְרָאָה אֹתוֹ הַכֹּהֵן וְהִנֵּה שְׂאֵת־הַנֶּגַע לְבָנָה אֲדַמְדֶּמֶת בְּקָרַחְתּוֹ אוֹ בְגַבַּחְתּוֹ כְּמַרְאֵה צָרַעַת עוֹר בָּשָׂר׃
אִישׁ־צָרוּעַ הוּא טָמֵא הוּא טַמֵּא יְטַמְּאֶנּוּ הַכֹּהֵן בְּרֹאשׁוֹ נִגְעוֹ׃
וְהַצָּרוּעַ אֲשֶׁר־בּוֹ הַנֶּגַע בְּגָדָיו יִהְיוּ פְרֻמִים וְרֹאשׁוֹ יִהְיֶה פָרוּעַ וְעַל־שָׂפָם יַעְטֶה וְטָמֵא טָמֵא יִקְרָא׃
כָּל־יְמֵי אֲשֶׁר הַנֶּגַע בּוֹ יִטְמָא טָמֵא הוּא בָּדָד יֵשֵׁב מִחוּץ לַמַּחֲנֶה מוֹשָׁבוֹ׃
וְהַבֶּגֶד כִּי־יִהְיֶה בוֹ נֶגַע צָרָעַת בְּבֶגֶד צֶמֶר אוֹ בְּבֶגֶד פִּשְׁתִּים׃
אוֹ בִשְׁתִי אוֹ בְעֵרֶב לַפִּשְׁתִּים וְלַצָּמֶר אוֹ בְעוֹר אוֹ בְּכָל־מְלֶאכֶת עוֹר׃
וְהָיָה הַנֶּגַע יְרַקְרַק אוֹ אֲדַמְדָּם בַּבֶּגֶד אוֹ בָעוֹר אוֹ־בַשְּׁתִי אוֹ־בָעֵרֶב אוֹ בְכָל־כְּלִי־עוֹר נֶגַע צָרַעַת הוּא וְהָרְאָה אֶת־הַכֹּהֵן׃
וְרָאָה הַכֹּהֵן אֶת־הַנָּגַע וְהִסְגִּיר אֶת־הַנֶּגַע שִׁבְעַת יָמִים׃
וְרָאָה אֶת־הַנֶּגַע בַּיּוֹם הַשְּׁבִיעִי כִּי־פָשָׂה הַנֶּגַע בַּבֶּגֶד אוֹ־בַשְּׁתִי אוֹ־בָעֵרֶב אוֹ בָעוֹר לְכֹל אֲשֶׁר־יֵעָשֶׂה הָעוֹר לִמְלָאכָה צָרַעַת מַמְאֶרֶת הַנֶּגַע טָמֵא הוּא׃
וְשָׂרַף אֶת־הַבֶּגֶד אוֹ אֶת־הַשְּׁתִי אוֹ אֶת־הָעֵרֶב בַּצֶּמֶר אוֹ בַפִּשְׁתִּים אוֹ אֶת־כָּל־כְּלִי הָעוֹר אֲשֶׁר־יִהְיֶה בוֹ הַנָּגַע כִּי־צָרַעַת מַמְאֶרֶת הִוא בָּאֵשׁ תִּשָּׂרֵף׃
וְאִם יִרְאֶה הַכֹּהֵן וְהִנֵּה לֹא־פָשָׂה הַנֶּגַע בַּבֶּגֶד אוֹ בַשְּׁתִי אוֹ בָעֵרֶב אוֹ בְּכָל־כְּלִי־עוֹר׃
וְצִוָּה הַכֹּהֵן וְכִבְּסוּ אֵת אֲשֶׁר־בּוֹ הַנָּגַע וְהִסְגִּירוֹ שִׁבְעַת־יָמִים שֵׁנִית׃
וְרָאָה הַכֹּהֵן אַחֲרֵי הֻכַּבֵּס אֶת־הַנֶּגַע וְהִנֵּה לֹא־הָפַךְ הַנֶּגַע אֶת־עֵינוֹ וְהַנֶּגַע לֹא־פָשָׂה טָמֵא הוּא בָּאֵשׁ תִּשְׂרְפֶנּוּ פְּחֶתֶת הִוא בְּקָרַחְתּוֹ אוֹ בְגַבַּחְתּוֹ׃
וְאִם רָאָה הַכֹּהֵן וְהִנֵּה כֵּהָה הַנֶּגַע אַחֲרֵי הֻכַּבֵּס אֹתוֹ וְקָרַע אֹתוֹ מִן־הַבֶּגֶד אוֹ מִן־הָעוֹר אוֹ מִן־הַשְּׁתִי אוֹ מִן־הָעֵרֶב׃
וְאִם־תֵּרָאֶה עוֹד בַּבֶּגֶד אוֹ־בַשְּׁתִי אוֹ־בָעֵרֶב אוֹ בְכָל־כְּלִי־עוֹר פֹּרַחַת הִוא בָּאֵשׁ תִּשְׂרְפֶנּוּ אֵת אֲשֶׁר־בּוֹ הַנָּגַע׃
וְהַבֶּגֶד אוֹ־הַשְּׁתִי אוֹ־הָעֵרֶב אוֹ־כָל־כְּלִי הָעוֹר אֲשֶׁר תְּכַבֵּס וְסָר מֵהֶם הַנָּגַע וְכֻבַּס שֵׁנִית וְטָהֵר׃
זֹאת תּוֹרַת נֶגַע־צָרַעַת בֶּגֶד הַצֶּמֶר אוֹ הַפִּשְׁתִּים אוֹ הַשְּׁתִי אוֹ הָעֵרֶב אוֹ כָּל־כְּלִי־עוֹר לְטַהֲרוֹ אוֹ לְטַמְּאוֹ׃

Chapter 14

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
זֹאת תִּהְיֶה תּוֹרַת הַמְּצֹרָע בְּיוֹם טָהֳרָתוֹ וְהוּבָא אֶל־הַכֹּהֵן׃
וְיָצָא הַכֹּהֵן אֶל־מִחוּץ לַמַּחֲנֶה וְרָאָה הַכֹּהֵן וְהִנֵּה נִרְפָּא נֶגַע־הַצָּרַעַת מִן־הַצָּרוּעַ׃
וְצִוָּה הַכֹּהֵן וְלָקַח לַמִּטַּהֵר שְׁתֵּי־צִפֳּרִים חַיּוֹת טְהֹרוֹת וְעֵץ אֶרֶז וּשְׁנִי תוֹלַעַת וְאֵזֹב׃
וְצִוָּה הַכֹּהֵן וְשָׁחַט אֶת־הַצִּפּוֹר הָאֶחָת אֶל־כְּלִי־חֶרֶשׂ עַל־מַיִם חַיִּים׃
אֶת־הַצִּפֹּר הַחַיָּה יִקַּח אֹתָהּ וְאֶת־עֵץ הָאֶרֶז וְאֶת־שְׁנִי הַתּוֹלַעַת וְאֶת־הָאֵזֹב וְטָבַל אוֹתָם וְאֵת הַצִּפֹּר הַחַיָּה בְּדַם הַצִּפֹּר הַשְּׁחֻטָה עַל הַמַּיִם הַחַיִּים׃
וְהִזָּה עַל הַמִּטַּהֵר מִן־הַצָּרַעַת שֶׁבַע פְּעָמִים וְטִהֲרוֹ וְשִׁלַּח אֶת־הַצִּפֹּר הַחַיָּה עַל־פְּנֵי הַשָּׂדֶה׃
וְכִבֶּס הַמִּטַּהֵר אֶת־בְּגָדָיו וְגִלַּח אֶת־כָּל־שְׂעָרוֹ וְרָחַץ בַּמַּיִם וְטָהֵר וְאַחַר יָבוֹא אֶל־הַמַּחֲנֶה וְיָשַׁב מִחוּץ לְאָהֳלוֹ שִׁבְעַת יָמִים׃
וְהָיָה בַיּוֹם הַשְּׁבִיעִי יְגַלַּח אֶת־כָּל־שְׂעָרוֹ אֶת־רֹאשׁוֹ וְאֶת־זְקָנוֹ וְאֵת גַּבֹּת עֵינָיו וְאֶת־כָּל־שְׂעָרוֹ יְגַלֵּחַ וְכִבֶּס אֶת־בְּגָדָיו וְרָחַץ אֶת־בְּשָׂרוֹ בַּמַּיִם וְטָהֵר׃
וּבַיּוֹם הַשְּׁמִינִי יִקַּח שְׁנֵי־כְבָשִׂים תְּמִימִים וְכַבְשָׂה אַחַת בַּת־שְׁנָתָהּ תְּמִימָה וּשְׁלֹשָׁה עֶשְׂרֹנִים סֹלֶת מִנְחָה בְּלוּלָה בַשֶּׁמֶן וְלֹג אֶחָד שָׁמֶן׃
וְהֶעֱמִיד הַכֹּהֵן הַמְטַהֵר אֵת הָאִישׁ הַמִּטַּהֵר וְאֹתָם לִפְנֵי יְהוָה פֶּתַח אֹהֶל מוֹעֵד׃
וְלָקַח הַכֹּהֵן אֶת־הַכֶּבֶשׂ הָאֶחָד וְהִקְרִיב אֹתוֹ לְאָשָׁם וְאֶת־לֹג הַשָּׁמֶן וְהֵנִיף אֹתָם תְּנוּפָה לִפְנֵי יְהוָה׃
וְשָׁחַט אֶת־הַכֶּבֶשׂ בִּמְקוֹם אֲשֶׁר יִשְׁחַט אֶת־הַחַטָּאת וְאֶת־הָעֹלָה בִּמְקוֹם הַקֹּדֶשׁ כִּי כַּחַטָּאת הָאָשָׁם הוּא לַכֹּהֵן קֹדֶשׁ קָדָשִׁים הוּא׃
וְלָקַח הַכֹּהֵן מִדַּם הָאָשָׁם וְנָתַן הַכֹּהֵן עַל־תְּנוּךְ אֹזֶן הַמִּטַּהֵר הַיְמָנִית וְעַל־בֹּהֶן יָדוֹ הַיְמָנִית וְעַל־בֹּהֶן רַגְלוֹ הַיְמָנִית׃
וְלָקַח הַכֹּהֵן מִלֹּג הַשָּׁמֶן וְיָצַק עַל־כַּף הַכֹּהֵן הַשְּׂמָאלִית׃
וְטָבַל הַכֹּהֵן אֶת־אֶצְבָּעוֹ הַיְמָנִית מִן־הַשֶּׁמֶן אֲשֶׁר עַל־כַּפּוֹ הַשְּׂמָאלִית וְהִזָּה מִן־הַשֶּׁמֶן בְּאֶצְבָּעוֹ שֶׁבַע פְּעָמִים לִפְנֵי יְהוָה׃
וּמִיֶּתֶר הַשֶּׁמֶן אֲשֶׁר עַל־כַּפּוֹ יִתֵּן הַכֹּהֵן עַל־תְּנוּךְ אֹזֶן הַמִּטַּהֵר הַיְמָנִית וְעַל־בֹּהֶן יָדוֹ הַיְמָנִית וְעַל־בֹּהֶן רַגְלוֹ הַיְמָנִית עַל דַּם הָאָשָׁם׃
וְהַנּוֹתָר בַּשֶּׁמֶן אֲשֶׁר עַל־כַּף הַכֹּהֵן יִתֵּן עַל־רֹאשׁ הַמִּטַּהֵר וְכִפֶּר עָלָיו הַכֹּהֵן לִפְנֵי יְהוָה׃
וְעָשָׂה הַכֹּהֵן אֶת־הַחַטָּאת וְכִפֶּר עַל־הַמִּטַּהֵר מִטֻּמְאָתוֹ וְאַחַר יִשְׁחַט אֶת־הָעֹלָה׃
וְהֶעֱלָה הַכֹּהֵן אֶת־הָעֹלָה וְאֶת־הַמִּנְחָה הַמִּזְבֵּחָה וְכִפֶּר עָלָיו הַכֹּהֵן וְטָהֵר׃
וְאִם־דַּל הוּא וְאֵין יָדוֹ מַשֶּׂגֶת וְלָקַח כֶּבֶשׂ אֶחָד אָשָׁם לִתְנוּפָה לְכַפֵּר עָלָיו וְעִשָּׂרוֹן סֹלֶת אֶחָד בָּלוּל בַּשֶּׁמֶן לְמִנְחָה וְלֹג שָׁמֶן׃
וּשְׁתֵּי תֹרִים אוֹ שְׁנֵי בְּנֵי יוֹנָה אֲשֶׁר תַּשִּׂיג יָדוֹ וְהָיָה אֶחָד חַטָּאת וְהָאֶחָד עֹלָה׃
וְהֵבִיא אֹתָם בַּיּוֹם הַשְּׁמִינִי לְטָהֳרָתוֹ אֶל־הַכֹּהֵן אֶל־פֶּתַח אֹהֶל־מוֹעֵד לִפְנֵי יְהוָה׃
וְלָקַח הַכֹּהֵן אֶת־כֶּבֶשׂ הָאָשָׁם וְאֶת־לֹג הַשָּׁמֶן וְהֵנִיף אֹתָם הַכֹּהֵן תְּנוּפָה לִפְנֵי יְהוָה׃
וְשָׁחַט אֶת־כֶּבֶשׂ הָאָשָׁם וְלָקַח הַכֹּהֵן מִדַּם הָאָשָׁם וְנָתַן עַל־תְּנוּךְ אֹזֶן־הַמִּטַּהֵר הַיְמָנִית וְעַל־בֹּהֶן יָדוֹ הַיְמָנִית וְעַל־בֹּהֶן רַגְלוֹ הַיְמָנִית׃
וּמִן־הַשֶּׁמֶן יִצֹק הַכֹּהֵן עַל־כַּף הַכֹּהֵן הַשְּׂמָאלִית׃
וְהִזָּה הַכֹּהֵן בְּאֶצְבָּעוֹ הַיְמָנִית מִן־הַשֶּׁמֶן אֲשֶׁר עַל־כַּפּוֹ הַשְּׂמָאלִית שֶׁבַע פְּעָמִים לִפְנֵי יְהוָה׃
וְנָתַן הַכֹּהֵן מִן־הַשֶּׁמֶן אֲשֶׁר עַל־כַּפּוֹ עַל־תְּנוּךְ אֹזֶן הַמִּטַּהֵר הַיְמָנִית וְעַל־בֹּהֶן יָדוֹ הַיְמָנִית וְעַל־בֹּהֶן רַגְלוֹ הַיְמָנִית עַל־מְקוֹם דַּם הָאָשָׁם׃
וְהַנּוֹתָר מִן־הַשֶּׁמֶן אֲשֶׁר עַל־כַּף הַכֹּהֵן יִתֵּן עַל־רֹאשׁ הַמִּטַּהֵר לְכַפֵּר עָלָיו לִפְנֵי יְהוָה׃
וְעָשָׂה אֶת־הָאֶחָד מִן־הַתֹּרִים אוֹ מִן־בְּנֵי הַיּוֹנָה מֵאֲשֶׁר תַּשִּׂיג יָדוֹ׃
אֵת אֲשֶׁר־תַּשִּׂיג יָדוֹ אֶת־הָאֶחָד חַטָּאת וְאֶת־הָאֶחָד עֹלָה עַל־הַמִּנְחָה וְכִפֶּר הַכֹּהֵן עַל הַמִּטַּהֵר לִפְנֵי יְהוָה׃
זֹאת תּוֹרַת אֲשֶׁר־בּוֹ נֶגַע צָרָעַת אֲשֶׁר לֹא־תַשִּׂיג יָדוֹ בְּטָהֳרָתוֹ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
כִּי תָבֹאוּ אֶל־אֶרֶץ כְּנַעַן אֲשֶׁר אֲנִי נֹתֵן לָכֶם לַאֲחֻזָּה וְנָתַתִּי נֶגַע צָרַעַת בְּבֵית אֶרֶץ אֲחֻזַּתְכֶם׃
וּבָא אֲשֶׁר־לוֹ הַבַּיִת וְהִגִּיד לַכֹּהֵן לֵאמֹר כְּנֶגַע נִרְאָה לִי בַּבָּיִת׃
וְצִוָּה הַכֹּהֵן וּפִנּוּ אֶת־הַבַּיִת בְּטֶרֶם יָבֹא הַכֹּהֵן לִרְאוֹת אֶת־הַנֶּגַע וְלֹא יִטְמָא כָּל־אֲשֶׁר בַּבָּיִת וְאַחַר כֵּן יָבֹא הַכֹּהֵן לִרְאוֹת אֶת־הַבָּיִת׃
וְרָאָה אֶת־הַנֶּגַע וְהִנֵּה הַנֶּגַע בְּקִירֹת הַבַּיִת שְׁקַעֲרוּרֹת יְרַקְרַקֹּת אוֹ אֲדַמְדַּמֹּת וּמַרְאֵיהֶן שָׁפָל מִן־הַקִּיר׃
וְיָצָא הַכֹּהֵן מִן־הַבַּיִת אֶל־פֶּתַח הַבָּיִת וְהִסְגִּיר אֶת־הַבַּיִת שִׁבְעַת יָמִים׃
וְשָׁב הַכֹּהֵן בַּיּוֹם הַשְּׁבִיעִי וְרָאָה וְהִנֵּה פָּשָׂה הַנֶּגַע בְּקִירֹת הַבָּיִת׃
וְצִוָּה הַכֹּהֵן וְחִלְּצוּ אֶת־הָאֲבָנִים אֲשֶׁר בָּהֵן הַנָּגַע וְהִשְׁלִיכוּ אֶתְהֶן אֶל־מִחוּץ לָעִיר אֶל־מָקוֹם טָמֵא׃
וְאֶת־הַבַּיִת יַקְצִעַ מִבַּיִת סָבִיב וְשָׁפְכוּ אֶת־הֶעָפָר אֲשֶׁר הִקְצוּ אֶל־מִחוּץ לָעִיר אֶל־מָקוֹם טָמֵא׃
וְלָקְחוּ אֲבָנִים אֲחֵרוֹת וְהֵבִיאוּ אֶל־תַּחַת הָאֲבָנִים וְעָפָר אַחֵר יִקַּח וְטָח אֶת־הַבָּיִת׃
וְאִם־יָשׁוּב הַנֶּגַע וּפָרַח בַּבַּיִת אַחַר חִלֵּץ אֶת־הָאֲבָנִים וְאַחֲרֵי הִקְצוֹת אֶת־הַבַּיִת וְאַחֲרֵי הִטּוֹחַ׃
וּבָא הַכֹּהֵן וְרָאָה וְהִנֵּה פָּשָׂה הַנֶּגַע בַּבָּיִת צָרַעַת מַמְאֶרֶת הִוא בַּבַּיִת טָמֵא הוּא׃
וְנָתַץ אֶת־הַבַּיִת אֶת־אֲבָנָיו וְאֶת־עֵצָיו וְאֵת כָּל־עֲפַר הַבָּיִת וְהוֹצִיא אֶל־מִחוּץ לָעִיר אֶל־מָקוֹם טָמֵא׃
וְהַבָּא אֶל־הַבַּיִת כָּל־יְמֵי הִסְגִּיר אֹתוֹ יִטְמָא עַד־הָעָרֶב׃
וְהַשֹּׁכֵב בַּבַּיִת יְכַבֵּס אֶת־בְּגָדָיו וְהָאֹכֵל בַּבַּיִת יְכַבֵּס אֶת־בְּגָדָיו׃
וְאִם־בֹּא יָבֹא הַכֹּהֵן וְרָאָה וְהִנֵּה לֹא־פָשָׂה הַנֶּגַע בַּבַּיִת אַחֲרֵי הִטֹּחַ אֶת־הַבָּיִת וְטִהַר הַכֹּהֵן אֶת־הַבַּיִת כִּי נִרְפָּא הַנָּגַע׃
וְלָקַח לְחַטֵּא אֶת־הַבַּיִת שְׁתֵּי צִפֳּרִים וְעֵץ אֶרֶז וּשְׁנִי תוֹלַעַת וְאֵזֹב׃
וְשָׁחַט אֶת־הַצִּפֹּר הָאֶחָת אֶל־כְּלִי־חֶרֶשׂ עַל־מַיִם חַיִּים׃
וְלָקַח אֶת־עֵץ־הָאֶרֶז וְאֶת־הָאֵזֹב וְאֵת שְׁנִי הַתּוֹלַעַת וְאֵת הַצִּפֹּר הַחַיָּה וְטָבַל אֹתָם בְּדַם הַצִּפֹּר הַשְּׁחוּטָה וּבַמַּיִם הַחַיִּים וְהִזָּה אֶל־הַבַּיִת שֶׁבַע פְּעָמִים׃
וְחִטֵּא אֶת־הַבַּיִת בְּדַם הַצִּפּוֹר וּבַמַּיִם הַחַיִּים וּבַצִּפֹּר הַחַיָּה וּבְעֵץ הָאֶרֶז וּבָאֵזֹב וּבִשְׁנִי הַתּוֹלָעַת׃
וְשִׁלַּח אֶת־הַצִּפֹּר הַחַיָּה אֶל־מִחוּץ לָעִיר אֶל־פְּנֵי הַשָּׂדֶה וְכִפֶּר עַל־הַבַּיִת וְטָהֵר׃
זֹאת הַתּוֹרָה לְכָל־נֶגַע הַצָּרַעַת וְלַנָּתֶק׃
וּלְצָרַעַת הַבֶּגֶד וְלַבָּיִת׃
וְלַשְׂאֵת וְלַסַּפַּחַת וְלַבֶּהָרֶת׃
לְהוֹרֹת בְּיוֹם הַטָּמֵא וּבְיוֹם הַטָּהֹר זֹאת תּוֹרַת הַצָּרָעַת׃

Chapter 15

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
דַּבְּרוּ אֶל־בְּנֵי יִשְׂרָאֵל וַאֲמַרְתֶּם אֲלֵהֶם אִישׁ אִישׁ כִּי יִהְיֶה זָב מִבְּשָׂרוֹ זוֹבוֹ טָמֵא הוּא׃
וְזֹאת תִּהְיֶה טֻמְאָתוֹ בְּזוֹבוֹ רָר בְּשָׂרוֹ אֶת־זוֹבוֹ אוֹ־הֶחְתִּים בְּשָׂרוֹ מִזּוֹבוֹ טֻמְאָתוֹ הִוא׃
כָּל־הַמִּשְׁכָּב אֲשֶׁר יִשְׁכַּב עָלָיו הַזָּב יִטְמָא וְכָל־הַכְּלִי אֲשֶׁר־יֵשֵׁב עָלָיו יִטְמָא׃
וְאִישׁ אֲשֶׁר יִגַּע בְּמִשְׁכָּבוֹ יְכַבֵּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְהַיֹּשֵׁב עַל־הַכְּלִי אֲשֶׁר־יֵשֵׁב עָלָיו הַזָּב יְכַבֵּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְהַנֹּגֵעַ בִּבְשַׂר הַזָּב יְכַבֵּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְכִי־יָרֹק הַזָּב בַּטָּהוֹר וְכִבֶּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְכָל־הַמֶּרְכָּב אֲשֶׁר יִרְכַּב עָלָיו הַזָּב יִטְמָא׃
וְכָל־הַנֹּגֵעַ בְּכֹל אֲשֶׁר יִהְיֶה תַחְתָּיו יִטְמָא עַד־הָעָרֶב וְהַנּוֹשֵׂא אוֹתָם יְכַבֵּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְכֹל אֲשֶׁר יִגַּע־בּוֹ הַזָּב וְיָדָיו לֹא־שָׁטַף בַּמָּיִם וְכִבֶּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וּכְלִי־חֶרֶשׂ אֲשֶׁר־יִגַּע־בּוֹ הַזָּב יִשָּׁבֵר וְכָל־כְּלִי־עֵץ יִשָּׁטֵף בַּמָּיִם׃
וְכִי־יִטְהַר הַזָּב מִזּוֹבוֹ וְסָפַר לוֹ שִׁבְעַת יָמִים לְטָהֳרָתוֹ וְכִבֶּס בְּגָדָיו וְרָחַץ בְּשָׂרוֹ בְּמַיִם חַיִּים וְטָהֵר׃
וּבַיּוֹם הַשְּׁמִינִי יִקַּח־לוֹ שְׁתֵּי תֹרִים אוֹ שְׁנֵי בְּנֵי יוֹנָה וּבָא לִפְנֵי יְהוָה אֶל־פֶּתַח אֹהֶל מוֹעֵד וּנְתָנָם אֶל־הַכֹּהֵן׃
וְעָשָׂה אֹתָם הַכֹּהֵן אֶחָד חַטָּאת וְהָאֶחָד עֹלָה וְכִפֶּר עָלָיו הַכֹּהֵן לִפְנֵי יְהוָה מִזּוֹבוֹ׃
וְאִישׁ כִּי־תֵצֵא מִמֶּנּוּ שִׁכְבַת־זָרַע וְרָחַץ בַּמַּיִם אֶת־כָּל־בְּשָׂרוֹ וְטָמֵא עַד־הָעָרֶב׃
וְכָל־בֶּגֶד וְכָל־עוֹר אֲשֶׁר־יִהְיֶה עָלָיו שִׁכְבַת־זָרַע וְכֻבַּס בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְאִשָּׁה אֲשֶׁר יִשְׁכַּב אִישׁ אֹתָהּ שִׁכְבַת־זָרַע וְרָחֲצוּ בַמַּיִם וְטָמְאוּ עַד־הָעָרֶב׃
וְאִשָּׁה כִּי־תִהְיֶה זָבָה דָּם יִהְיֶה זֹבָהּ בִּבְשָׂרָהּ שִׁבְעַת יָמִים תִּהְיֶה בְנִדָּתָהּ וְכָל־הַנֹּגֵעַ בָּהּ יִטְמָא עַד־הָעָרֶב׃
וְכֹל אֲשֶׁר תִּשְׁכַּב עָלָיו בְּנִדָּתָהּ יִטְמָא וְכֹל אֲשֶׁר־תֵּשֵׁב עָלָיו יִטְמָא׃
וְכָל־הַנֹּגֵעַ בְּמִשְׁכָּבָהּ יְכַבֵּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְכָל־הַנֹּגֵעַ בְּכָל־כְּלִי אֲשֶׁר־תֵּשֵׁב עָלָיו יְכַבֵּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְאִם עַל־הַמִּשְׁכָּב הוּא אוֹ עַל־הַכְּלִי אֲשֶׁר־הִוא יֹשֶׁבֶת־עָלָיו בְּנָגְעוֹ־בוֹ יִטְמָא עַד־הָעָרֶב׃
וְאִם שָׁכֹב יִשְׁכַּב אִישׁ אֹתָהּ וּתְהִי נִדָּתָהּ עָלָיו וְטָמֵא שִׁבְעַת יָמִים וְכָל־הַמִּשְׁכָּב אֲשֶׁר־יִשְׁכַּב עָלָיו יִטְמָא׃
וְאִשָּׁה כִּי־יָזוּב זוֹב דָּמָהּ יָמִים רַבִּים בְּלֹא עֶת־נִדָּתָהּ אוֹ כִי־תָזוּב עַל־נִדָּתָהּ כָּל־יְמֵי זוֹב טֻמְאָתָהּ כִּימֵי נִדָּתָהּ תִּהְיֶה טְמֵאָה הִוא׃
כָּל־הַמִּשְׁכָּב אֲשֶׁר־תִּשְׁכַּב עָלָיו כָּל־יְמֵי זוֹבָהּ כְּמִשְׁכַּב נִדָּתָהּ יִהְיֶה־לָּהּ וְכָל־הַכְּלִי אֲשֶׁר תֵּשֵׁב עָלָיו טָמֵא יִהְיֶה כְּטֻמְאַת נִדָּתָהּ׃
וְכָל־הַנּוֹגֵעַ בָּם יִטְמָא וְכִבֶּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעָרֶב׃
וְאִם־טָהֲרָה מִזּוֹבָהּ וְסָפְרָה לָּהּ שִׁבְעַת יָמִים וְאַחַר תִּטְהָר׃
וּבַיּוֹם הַשְּׁמִינִי תִּקַּח־לָהּ שְׁתֵּי תֹרִים אוֹ שְׁנֵי בְּנֵי יוֹנָה וְהֵבִיאָה אוֹתָם אֶל־הַכֹּהֵן אֶל־פֶּתַח אֹהֶל מוֹעֵד׃
וְעָשָׂה הַכֹּהֵן אֶת־הָאֶחָד חַטָּאת וְאֶת־הָאֶחָד עֹלָה וְכִפֶּר עָלֶיהָ הַכֹּהֵן לִפְנֵי יְהוָה מִזּוֹב טֻמְאָתָהּ׃
וְהִזַּרְתֶּם אֶת־בְּנֵי־יִשְׂרָאֵל מִטֻּמְאָתָם וְלֹא יָמֻתוּ בְּטֻמְאָתָם בְּטַמְּאָם אֶת־מִשְׁכָּנִי אֲשֶׁר בְּתוֹכָם׃
זֹאת תּוֹרַת הַזָּב וַאֲשֶׁר תֵּצֵא מִמֶּנּוּ שִׁכְבַת־זֶרַע לְטָמְאָה־בָהּ׃
וְהַדָּוָה בְּנִדָּתָהּ וְהַזָּב אֶת־זוֹבוֹ לַזָּכָר וְלַנְּקֵבָה וּלְאִישׁ אֲשֶׁר יִשְׁכַּב עִם־טְמֵאָה׃

Chapter 16

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה אַחֲרֵי מוֹת שְׁנֵי בְּנֵי אַהֲרֹן בְּקָרְבָתָם לִפְנֵי־יְהוָה וַיָּמֻתוּ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה דַּבֵּר אֶל־אַהֲרֹן אָחִיךָ וְאַל־יָבֹא בְכָל־עֵת אֶל־הַקֹּדֶשׁ מִבֵּית לַפָּרֹכֶת אֶל־פְּנֵי הַכַּפֹּרֶת אֲשֶׁר עַל־הָאָרֹן וְלֹא יָמוּת כִּי בֶּעָנָן אֵרָאֶה עַל־הַכַּפֹּרֶת׃
בְּזֹאת יָבֹא אַהֲרֹן אֶל־הַקֹּדֶשׁ בְּפַר בֶּן־בָּקָר לְחַטָּאת וְאַיִל לְעֹלָה׃
כְּתֹנֶת־בַּד קֹדֶשׁ יִלְבָּשׁ וּמִכְנְסֵי־בַד יִהְיוּ עַל־בְּשָׂרוֹ וּבְאַבְנֵט בַּד יַחְגֹּר וּבְמִצְנֶפֶת בַּד יִצְנֹף בִּגְדֵי־קֹדֶשׁ הֵם וְרָחַץ בַּמַּיִם אֶת־בְּשָׂרוֹ וּלְבֵשָׁם׃
וּמֵאֵת עֲדַת בְּנֵי יִשְׂרָאֵל יִקַּח שְׁנֵי־שְׂעִירֵי עִזִּים לְחַטָּאת וְאַיִל אֶחָד לְעֹלָה׃
וְהִקְרִיב אַהֲרֹן אֶת־פַּר הַחַטָּאת אֲשֶׁר־לוֹ וְכִפֶּר בַּעֲדוֹ וּבְעַד בֵּיתוֹ׃
וְלָקַח אֶת־שְׁנֵי הַשְּׂעִירִם וְהֶעֱמִיד אֹתָם לִפְנֵי יְהוָה פֶּתַח אֹהֶל מוֹעֵד׃
וְנָתַן אַהֲרֹן עַל־שְׁנֵי הַשְּׂעִירִם גּוֹרָלוֹת גּוֹרָל אֶחָד לַיהוָה וְגוֹרָל אֶחָד לַעֲזָאזֵל׃
וְהִקְרִיב אַהֲרֹן אֶת־הַשָּׂעִיר אֲשֶׁר עָלָה עָלָיו הַגּוֹרָל לַיהוָה וְעָשָׂהוּ חַטָּאת׃
וְהַשָּׂעִיר אֲשֶׁר עָלָה עָלָיו הַגּוֹרָל לַעֲזָאזֵל יָעֳמַד־חַי לִפְנֵי יְהוָה לְכַפֵּר עָלָיו לְשַׁלַּח אֹתוֹ לַעֲזָאזֵל הַמִּדְבָּרָה׃
וְהִקְרִיב אַהֲרֹן אֶת־פַּר הַחַטָּאת אֲשֶׁר־לוֹ וְכִפֶּר בַּעֲדוֹ וּבְעַד בֵּיתוֹ וְשָׁחַט אֶת־פַּר הַחַטָּאת אֲשֶׁר־לוֹ׃
וְלָקַח מְלֹא־הַמַּחְתָּה גַּחֲלֵי־אֵשׁ מֵעַל הַמִּזְבֵּחַ מִלִּפְנֵי יְהוָה וּמְלֹא חָפְנָיו קְטֹרֶת סַמִּים דַּקָּה וְהֵבִיא מִבֵּית לַפָּרֹכֶת׃
וְנָתַן אֶת־הַקְּטֹרֶת עַל־הָאֵשׁ לִפְנֵי יְהוָה וְכִסָּה עֲנַן הַקְּטֹרֶת אֶת־הַכַּפֹּרֶת אֲשֶׁר עַל־הָעֵדוּת וְלֹא יָמוּת׃
וְלָקַח מִדַּם הַפָּר וְהִזָּה בְאֶצְבָּעוֹ עַל־פְּנֵי הַכַּפֹּרֶת קֵדְמָה וְלִפְנֵי הַכַּפֹּרֶת יַזֶּה שֶׁבַע־פְּעָמִים מִן־הַדָּם בְּאֶצְבָּעוֹ׃
וְשָׁחַט אֶת־שְׂעִיר הַחַטָּאת אֲשֶׁר לָעָם וְהֵבִיא אֶת־דָּמוֹ אֶל־מִבֵּית לַפָּרֹכֶת וְעָשָׂה אֶת־דָּמוֹ כַּאֲשֶׁר עָשָׂה לְדַם הַפָּר וְהִזָּה אֹתוֹ עַל־הַכַּפֹּרֶת וְלִפְנֵי הַכַּפֹּרֶת׃
וְכִפֶּר עַל־הַקֹּדֶשׁ מִטֻּמְאֹת בְּנֵי יִשְׂרָאֵל וּמִפִּשְׁעֵיהֶם לְכָל־חַטֹּאתָם וְכֵן יַעֲשֶׂה לְאֹהֶל מוֹעֵד הַשֹּׁכֵן אִתָּם בְּתוֹךְ טֻמְאֹתָם׃
וְכָל־אָדָם לֹא־יִהְיֶה בְּאֹהֶל מוֹעֵד בְּבֹאוֹ לְכַפֵּר בַּקֹּדֶשׁ עַד־צֵאתוֹ וְכִפֶּר בַּעֲדוֹ וּבְעַד בֵּיתוֹ וּבְעַד כָּל־קְהַל יִשְׂרָאֵל׃
וְיָצָא אֶל־הַמִּזְבֵּחַ אֲשֶׁר לִפְנֵי־יְהוָה וְכִפֶּר עָלָיו וְלָקַח מִדַּם הַפָּר וּמִדַּם הַשָּׂעִיר וְנָתַן עַל־קַרְנוֹת הַמִּזְבֵּחַ סָבִיב׃
וְהִזָּה עָלָיו מִן־הַדָּם בְּאֶצְבָּעוֹ שֶׁבַע פְּעָמִים וְטִהֲרוֹ וְקִדְּשׁוֹ מִטֻּמְאֹת בְּנֵי יִשְׂרָאֵל׃
וְכִלָּה מִכַּפֵּר אֶת־הַקֹּדֶשׁ וְאֶת־אֹהֶל מוֹעֵד וְאֶת־הַמִּזְבֵּחַ וְהִקְרִיב אֶת־הַשָּׂעִיר הֶחָי׃
וְסָמַךְ אַהֲרֹן אֶת־שְׁתֵּי ידו [יָדָיו] עַל רֹאשׁ הַשָּׂעִיר הַחַי וְהִתְוַדָּה עָלָיו אֶת־כָּל־עֲוֺנֹת בְּנֵי יִשְׂרָאֵל וְאֶת־כָּל־פִּשְׁעֵיהֶם לְכָל־חַטֹּאתָם וְנָתַן אֹתָם עַל־רֹאשׁ הַשָּׂעִיר וְשִׁלַּח בְּיַד־אִישׁ עִתִּי הַמִּדְבָּרָה׃
וְנָשָׂא הַשָּׂעִיר עָלָיו אֶת־כָּל־עֲוֺנֹתָם אֶל־אֶרֶץ גְּזֵרָה וְשִׁלַּח אֶת־הַשָּׂעִיר בַּמִּדְבָּר׃
וּבָא אַהֲרֹן אֶל־אֹהֶל מוֹעֵד וּפָשַׁט אֶת־בִּגְדֵי הַבָּד אֲשֶׁר לָבַשׁ בְּבֹאוֹ אֶל־הַקֹּדֶשׁ וְהִנִּיחָם שָׁם׃
וְרָחַץ אֶת־בְּשָׂרוֹ בַמַּיִם בְּמָקוֹם קָדוֹשׁ וְלָבַשׁ אֶת־בְּגָדָיו וְיָצָא וְעָשָׂה אֶת־עֹלָתוֹ וְאֶת־עֹלַת הָעָם וְכִפֶּר בַּעֲדוֹ וּבְעַד הָעָם׃
וְאֵת חֵלֶב הַחַטָּאת יַקְטִיר הַמִּזְבֵּחָה׃
וְהַמְשַׁלֵּחַ אֶת־הַשָּׂעִיר לַעֲזָאזֵל יְכַבֵּס בְּגָדָיו וְרָחַץ אֶת־בְּשָׂרוֹ בַּמָּיִם וְאַחֲרֵי־כֵן יָבוֹא אֶל־הַמַּחֲנֶה׃
וְאֵת פַּר הַחַטָּאת וְאֵת שְׂעִיר הַחַטָּאת אֲשֶׁר הוּבָא אֶת־דָּמָם לְכַפֵּר בַּקֹּדֶשׁ יוֹצִיא אֶל־מִחוּץ לַמַּחֲנֶה וְשָׂרְפוּ בָאֵשׁ אֶת־עֹרֹתָם וְאֶת־בְּשָׂרָם וְאֶת־פִּרְשָׁם׃
וְהַשֹּׂרֵף אֹתָם יְכַבֵּס בְּגָדָיו וְרָחַץ אֶת־בְּשָׂרוֹ בַּמָּיִם וְאַחֲרֵי־כֵן יָבוֹא אֶל־הַמַּחֲנֶה׃
וְהָיְתָה לָכֶם לְחֻקַּת עוֹלָם בַּחֹדֶשׁ הַשְּׁבִיעִי בֶּעָשׂוֹר לַחֹדֶשׁ תְּעַנּוּ אֶת־נַפְשֹׁתֵיכֶם וְכָל־מְלָאכָה לֹא תַעֲשׂוּ הָאֶזְרָח וְהַגֵּר הַגָּר בְּתוֹכְכֶם׃
כִּי־בַיּוֹם הַזֶּה יְכַפֵּר עֲלֵיכֶם לְטַהֵר אֶתְכֶם מִכֹּל חַטֹּאתֵיכֶם לִפְנֵי יְהוָה תִּטְהָרוּ׃
שַׁבַּת שַׁבָּתוֹן הִיא לָכֶם וְעִנִּיתֶם אֶת־נַפְשֹׁתֵיכֶם חֻקַּת עוֹלָם׃
וְכִפֶּר הַכֹּהֵן אֲשֶׁר־יִמְשַׁח אֹתוֹ וַאֲשֶׁר יְמַלֵּא אֶת־יָדוֹ לְכַהֵן תַּחַת אָבִיו וְלָבַשׁ אֶת־בִּגְדֵי הַבָּד בִּגְדֵי הַקֹּדֶשׁ׃
וְכִפֶּר אֶת־מִקְדַּשׁ הַקֹּדֶשׁ וְאֶת־אֹהֶל מוֹעֵד וְאֶת־הַמִּזְבֵּחַ יְכַפֵּר וְעַל הַכֹּהֲנִים וְעַל־כָּל־עַם הַקָּהָל יְכַפֵּר׃
וְהָיְתָה־זֹּאת לָכֶם לְחֻקַּת עוֹלָם לְכַפֵּר עַל־בְּנֵי יִשְׂרָאֵל מִכָּל־חַטֹּאתָם אַחַת בַּשָּׁנָה וַיַּעַשׂ כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃

Chapter 17

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־אַהֲרֹן וְאֶל־בָּנָיו וְאֶל כָּל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵיהֶם זֶה הַדָּבָר אֲשֶׁר־צִוָּה יְהוָה לֵאמֹר׃
אִישׁ אִישׁ מִבֵּית יִשְׂרָאֵל אֲשֶׁר יִשְׁחַט שׁוֹר אוֹ־כֶשֶׂב אוֹ־עֵז בַּמַּחֲנֶה אוֹ אֲשֶׁר יִשְׁחַט מִחוּץ לַמַּחֲנֶה׃
וְאֶל־פֶּתַח אֹהֶל מוֹעֵד לֹא הֱבִיאוֹ לְהַקְרִיב קָרְבָּן לַיהוָה לִפְנֵי מִשְׁכַּן יְהוָה דָּם יֵחָשֵׁב לָאִישׁ הַהוּא דָּם שָׁפָךְ וְנִכְרַת הָאִישׁ הַהוּא מִקֶּרֶב עַמּוֹ׃
לְמַעַן אֲשֶׁר יָבִיאוּ בְּנֵי יִשְׂרָאֵל אֶת־זִבְחֵיהֶם אֲשֶׁר הֵם זֹבְחִים עַל־פְּנֵי הַשָּׂדֶה וֶהֱבִיאֻם לַיהוָה אֶל־פֶּתַח אֹהֶל מוֹעֵד אֶל־הַכֹּהֵן וְזָבְחוּ זִבְחֵי שְׁלָמִים לַיהוָה אוֹתָם׃
וְזָרַק הַכֹּהֵן אֶת־הַדָּם עַל־מִזְבַּח יְהוָה פֶּתַח אֹהֶל מוֹעֵד וְהִקְטִיר הַחֵלֶב לְרֵיחַ נִיחֹחַ לַיהוָה׃
וְלֹא־יִזְבְּחוּ עוֹד אֶת־זִבְחֵיהֶם לַשְּׂעִירִם אֲשֶׁר הֵם זֹנִים אַחֲרֵיהֶם חֻקַּת עוֹלָם תִּהְיֶה־זֹּאת לָהֶם לְדֹרֹתָם׃
וַאֲלֵהֶם תֹּאמַר אִישׁ אִישׁ מִבֵּית יִשְׂרָאֵל וּמִן־הַגֵּר אֲשֶׁר־יָגוּר בְּתוֹכָם אֲשֶׁר־יַעֲלֶה עֹלָה אוֹ־זָבַח׃
וְאֶל־פֶּתַח אֹהֶל מוֹעֵד לֹא יְבִיאֶנּוּ לַעֲשׂוֹת אֹתוֹ לַיהוָה וְנִכְרַת הָאִישׁ הַהוּא מֵעַמָּיו׃
וְאִישׁ אִישׁ מִבֵּית יִשְׂרָאֵל וּמִן־הַגֵּר הַגָּר בְּתוֹכָם אֲשֶׁר יֹאכַל כָּל־דָּם וְנָתַתִּי פָנַי בַּנֶּפֶשׁ הָאֹכֶלֶת אֶת־הַדָּם וְהִכְרַתִּי אֹתָהּ מִקֶּרֶב עַמָּהּ׃
כִּי נֶפֶשׁ הַבָּשָׂר בַּדָּם הִוא וַאֲנִי נְתַתִּיו לָכֶם עַל־הַמִּזְבֵּחַ לְכַפֵּר עַל־נַפְשֹׁתֵיכֶם כִּי־הַדָּם הוּא בַּנֶּפֶשׁ יְכַפֵּר׃
עַל־כֵּן אָמַרְתִּי לִבְנֵי יִשְׂרָאֵל כָּל־נֶפֶשׁ מִכֶּם לֹא־תֹאכַל דָּם וְהַגֵּר הַגָּר בְּתוֹכְכֶם לֹא־יֹאכַל דָּם׃
וְאִישׁ אִישׁ מִבְּנֵי יִשְׂרָאֵל וּמִן־הַגֵּר הַגָּר בְּתוֹכָם אֲשֶׁר יָצוּד צֵיד חַיָּה אוֹ־עוֹף אֲשֶׁר יֵאָכֵל וְשָׁפַךְ אֶת־דָּמוֹ וְכִסָּהוּ בֶּעָפָר׃
כִּי־נֶפֶשׁ כָּל־בָּשָׂר דָּמוֹ בְנַפְשׁוֹ הוּא וָאֹמַר לִבְנֵי יִשְׂרָאֵל דַּם כָּל־בָּשָׂר לֹא תֹאכֵלוּ כִּי נֶפֶשׁ כָּל־בָּשָׂר דָּמוֹ הִוא כָּל־אֹכְלָיו יִכָּרֵת׃
וְכָל־נֶפֶשׁ אֲשֶׁר תֹּאכַל נְבֵלָה וּטְרֵפָה בָּאֶזְרָח וּבַגֵּר וְכִבֶּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָמֵא עַד־הָעֶרֶב וְטָהֵר׃
וְאִם לֹא יְכַבֵּס וּבְשָׂרוֹ לֹא יִרְחָץ וְנָשָׂא עֲוֺנוֹ׃

Chapter 18

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
כְּמַעֲשֵׂה אֶרֶץ־מִצְרַיִם אֲשֶׁר יְשַׁבְתֶּם־בָּהּ לֹא תַעֲשׂוּ וּכְמַעֲשֵׂה אֶרֶץ־כְּנַעַן אֲשֶׁר אֲנִי מֵבִיא אֶתְכֶם שָׁמָּה לֹא תַעֲשׂוּ וּבְחֻקֹּתֵיהֶם לֹא תֵלֵכוּ׃
אֶת־מִשְׁפָּטַי תַּעֲשׂוּ וְאֶת־חֻקֹּתַי תִּשְׁמְרוּ לָלֶכֶת בָּהֶם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וּשְׁמַרְתֶּם אֶת־חֻקֹּתַי וְאֶת־מִשְׁפָּטַי אֲשֶׁר יַעֲשֶׂה אֹתָם הָאָדָם וָחַי בָּהֶם אֲנִי יְהוָה׃
אִישׁ אִישׁ אֶל־כָּל־שְׁאֵר בְּשָׂרוֹ לֹא תִקְרְבוּ לְגַלּוֹת עֶרְוָה אֲנִי יְהוָה׃
עֶרְוַת אָבִיךָ וְעֶרְוַת אִמְּךָ לֹא תְגַלֵּה אִמְּךָ הִוא לֹא תְגַלֶּה עֶרְוָתָהּ׃
עֶרְוַת אֵשֶׁת־אָבִיךָ לֹא תְגַלֵּה עֶרְוַת אָבִיךָ הִוא׃
עֶרְוַת אֲחוֹתְךָ בַת־אָבִיךָ אוֹ בַת־אִמֶּךָ מוֹלֶדֶת בַּיִת אוֹ מוֹלֶדֶת חוּץ לֹא תְגַלֶּה עֶרְוָתָן׃
עֶרְוַת בַּת־בִּנְךָ אוֹ בַת־בִּתְּךָ לֹא תְגַלֶּה עֶרְוָתָן כִּי עֶרְוָתְךָ הֵנָּה׃
עֶרְוַת בַּת־אֵשֶׁת אָבִיךָ מוֹלֶדֶת אָבִיךָ אֲחוֹתְךָ הִוא לֹא תְגַלֶּה עֶרְוָתָהּ׃
עֶרְוַת אֲחוֹת־אָבִיךָ לֹא תְגַלֵּה שְׁאֵר אָבִיךָ הִוא׃
עֶרְוַת אֲחוֹת־אִמְּךָ לֹא תְגַלֵּה כִּי־שְׁאֵר אִמְּךָ הִוא׃
עֶרְוַת אֲחִי־אָבִיךָ לֹא תְגַלֵּה אֶל־אִשְׁתּוֹ לֹא תִקְרָב דֹּדָתְךָ הִוא׃
עֶרְוַת כַּלָּתְךָ לֹא תְגַלֵּה אֵשֶׁת בִּנְךָ הִוא לֹא תְגַלֶּה עֶרְוָתָהּ׃
עֶרְוַת אֵשֶׁת־אָחִיךָ לֹא תְגַלֵּה עֶרְוַת אָחִיךָ הִוא׃
עֶרְוַת אִשָּׁה וּבִתָּהּ לֹא תְגַלֵּה אֶת־בַּת־בְּנָהּ וְאֶת־בַּת־בִּתָּהּ לֹא תִקַּח לְגַלּוֹת עֶרְוָתָהּ שַׁאֲרָה הֵנָּה זִמָּה הִוא
וְאִשָּׁה אֶל־אֲחֹתָהּ לֹא תִקָּח לִצְרֹר לְגַלּוֹת עֶרְוָתָהּ עָלֶיהָ בְּחַיֶּיהָ׃
וְאֶל־אִשָּׁה בְּנִדַּת טֻמְאָתָהּ לֹא תִקְרַב לְגַלּוֹת עֶרְוָתָהּ׃
וְאֶל־אֵשֶׁת עֲמִיתְךָ לֹא־תִתֵּן שְׁכָבְתְּךָ לְזָרַע לְטָמְאָה־בָהּ׃
וּמִזַּרְעֲךָ לֹא־תִתֵּן לְהַעֲבִיר לַמֹּלֶךְ וְלֹא תְחַלֵּל אֶת־שֵׁם אֱלֹהֶיךָ אֲנִי יְהוָה׃
וְאֶת־זָכָר לֹא תִשְׁכַּב מִשְׁכְּבֵי אִשָּׁה תּוֹעֵבָה הִוא׃
וּבְכָל־בְּהֵמָה לֹא־תִתֵּן שְׁכָבְתְּךָ לְטָמְאָה־בָהּ וְאִשָּׁה לֹא־תַעֲמֹד לִפְנֵי בְהֵמָה לְרִבְעָהּ תֶּבֶל הוּא׃
אַל־תִּטַּמְּאוּ בְּכָל־אֵלֶּה כִּי בְכָל־אֵלֶּה נִטְמְאוּ הַגּוֹיִם אֲשֶׁר־אֲנִי מְשַׁלֵּחַ מִפְּנֵיכֶם׃
וַתִּטְמָא הָאָרֶץ וָאֶפְקֹד עֲוֺנָהּ עָלֶיהָ וַתָּקִא הָאָרֶץ אֶת־יֹשְׁבֶיהָ׃
וּשְׁמַרְתֶּם אַתֶּם אֶת־חֻקֹּתַי וְאֶת־מִשְׁפָּטַי וְלֹא תַעֲשׂוּ מִכֹּל הַתּוֹעֵבֹת הָאֵלֶּה הָאֶזְרָח וְהַגֵּר הַגָּר בְּתוֹכְכֶם׃
כִּי אֶת־כָּל־הַתּוֹעֵבֹת הָאֵל עָשׂוּ אַנְשֵׁי־הָאָרֶץ אֲשֶׁר לִפְנֵיכֶם וַתִּטְמָא הָאָרֶץ׃
וְלֹא־תָקִיא הָאָרֶץ אֶתְכֶם בְּטַמַּאֲכֶם אֹתָהּ כַּאֲשֶׁר קָאָה אֶת־הַגּוֹי אֲשֶׁר לִפְנֵיכֶם׃
כִּי כָּל־אֲשֶׁר יַעֲשֶׂה מִכֹּל הַתּוֹעֵבוֹת הָאֵלֶּה וְנִכְרְתוּ הַנְּפָשׁוֹת הָעֹשֹׂת מִקֶּרֶב עַמָּם׃
וּשְׁמַרְתֶּם אֶת־מִשְׁמַרְתִּי לְבִלְתִּי עֲשׂוֹת מֵחֻקּוֹת הַתּוֹעֵבֹת אֲשֶׁר נַעֲשׂוּ לִפְנֵיכֶם וְלֹא תִטַּמְּאוּ בָּהֶם אֲנִי יְהוָה אֱלֹהֵיכֶם׃

Chapter 19

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר
דַּבֵּר אֶל־כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם קְדֹשִׁים תִּהְיוּ כִּי קָדוֹשׁ אֲנִי יְהוָה אֱלֹהֵיכֶם׃
אִישׁ אִמּוֹ וְאָבִיו תִּירָאוּ וְאֶת־שַׁבְּתֹתַי תִּשְׁמֹרוּ אֲנִי יְהוָה אֱלֹהֵיכֶם׃
אַל־תִּפְנוּ אֶל־הָאֱלִילִים וֵאלֹהֵי מַסֵּכָה לֹא תַעֲשׂוּ לָכֶם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וְכִי תִזְבְּחוּ זֶבַח שְׁלָמִים לַיהוָה לִרְצֹנְכֶם תִּזְבָּחֻהוּ׃
בְּיוֹם זִבְחֲכֶם יֵאָכֵל וּמִמָּחֳרָת וְהַנּוֹתָר עַד־יוֹם הַשְּׁלִישִׁי בָּאֵשׁ יִשָּׂרֵף׃
וְאִם הֵאָכֹל יֵאָכֵל בַּיּוֹם הַשְּׁלִישִׁי פִּגּוּל הוּא לֹא יֵרָצֶה׃
וְאֹכְלָיו עֲוֺנוֹ יִשָּׂא כִּי־אֶת־קֹדֶשׁ יְהוָה חִלֵּל וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מֵעַמֶּיהָ׃
וּבְקֻצְרְכֶם אֶת־קְצִיר אַרְצְכֶם לֹא תְכַלֶּה פְּאַת שָׂדְךָ לִקְצֹר וְלֶקֶט קְצִירְךָ לֹא תְלַקֵּט׃
וְכַרְמְךָ לֹא תְעוֹלֵל וּפֶרֶט כַּרְמְךָ לֹא תְלַקֵּט לֶעָנִי וְלַגֵּר תַּעֲזֹב אֹתָם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
לֹא תִּגְנֹבוּ וְלֹא־תְכַחֲשׁוּ וְלֹא־תְשַׁקְּרוּ אִישׁ בַּעֲמִיתוֹ׃
וְלֹא־תִשָּׁבְעוּ בִשְׁמִי לַשָּׁקֶר וְחִלַּלְתָּ אֶת־שֵׁם אֱלֹהֶיךָ אֲנִי יְהוָה׃
לֹא־תַעֲשֹׁק אֶת־רֵעֲךָ וְלֹא תִגְזֹל לֹא־תָלִין פְּעֻלַּת שָׂכִיר אִתְּךָ עַד־בֹּקֶר׃
לֹא־תְקַלֵּל חֵרֵשׁ וְלִפְנֵי עִוֵּר לֹא תִתֵּן מִכְשֹׁל וְיָרֵאתָ מֵּאֱלֹהֶיךָ אֲנִי יְהוָה׃
לֹא־תַעֲשׂוּ עָוֶל בַּמִּשְׁפָּט לֹא־תִשָּׂא פְנֵי־דָל וְלֹא תֶהְדַּר פְּנֵי גָדוֹל בְּצֶדֶק תִּשְׁפֹּט עֲמִיתֶךָ׃
לֹא־תֵלֵךְ רָכִיל בְּעַמֶּיךָ לֹא תַעֲמֹד עַל־דַּם רֵעֶךָ אֲנִי יְהוָה׃
לֹא־תִשְׂנָא אֶת־אָחִיךָ בִּלְבָבֶךָ הוֹכֵחַ תּוֹכִיחַ אֶת־עֲמִיתֶךָ וְלֹא־תִשָּׂא עָלָיו חֵטְא׃
לֹא־תִקֹּם וְלֹא־תִטֹּר אֶת־בְּנֵי עַמֶּךָ וְאָהַבְתָּ לְרֵעֲךָ כָּמוֹךָ אֲנִי יְהוָה׃
אֶת־חֻקֹּתַי תִּשְׁמֹרוּ בְּהֶמְתְּךָ לֹא־תַרְבִּיעַ כִּלְאַיִם שָׂדְךָ לֹא־תִזְרַע כִּלְאָיִם וּבֶגֶד כִּלְאַיִם שַׁעַטְנֵז לֹא יַעֲלֶה עָלֶיךָ׃
וְאִישׁ כִּי־יִשְׁכַּב אֶת־אִשָּׁה שִׁכְבַת־זֶרַע וְהִוא שִׁפְחָה נֶחֱרֶפֶת לְאִישׁ וְהָפְדֵּה לֹא נִפְדָּתָה אוֹ חֻפְשָׁה לֹא נִתַּן־לָהּ בִּקֹּרֶת תִּהְיֶה לֹא יוּמְתוּ כִּי־לֹא חֻפָּשָׁה׃
וְהֵבִיא אֶת־אֲשָׁמוֹ לַיהוָה אֶל־פֶּתַח אֹהֶל מוֹעֵד אֵיל אָשָׁם׃
וְכִפֶּר עָלָיו הַכֹּהֵן בְּאֵיל הָאָשָׁם לִפְנֵי יְהוָה עַל־חַטָּאתוֹ אֲשֶׁר חָטָא וְנִסְלַח לוֹ מֵחַטָּאתוֹ אֲשֶׁר חָטָא׃
וְכִי־תָבֹאוּ אֶל־הָאָרֶץ וּנְטַעְתֶּם כָּל־עֵץ מַאֲכָל וַעֲרַלְתֶּם עָרְלָתוֹ אֶת־פִּרְיוֹ שָׁלֹשׁ שָׁנִים יִהְיֶה לָכֶם עֲרֵלִים לֹא יֵאָכֵל׃
וּבַשָּׁנָה הָרְבִיעִת יִהְיֶה כָּל־פִּרְיוֹ קֹדֶשׁ הִלּוּלִים לַיהוָה׃
וּבַשָּׁנָה הַחֲמִישִׁת תֹּאכְלוּ אֶת־פִּרְיוֹ לְהוֹסִיף לָכֶם תְּבוּאָתוֹ אֲנִי יְהוָה אֱלֹהֵיכֶם׃
לֹא תֹאכְלוּ עַל־הַדָּם לֹא תְנַחֲשׁוּ וְלֹא תְעוֹנֵנוּ׃
לֹא תַקִּפוּ פְּאַת רֹאשְׁכֶם וְלֹא תַשְׁחִית אֵת פְּאַת זְקָנֶךָ׃
וְשֶׂרֶט לָנֶפֶשׁ לֹא תִתְּנוּ בִּבְשַׂרְכֶם וּכְתֹבֶת קַעֲקַע לֹא תִתְּנוּ בָּכֶם אֲנִי יְהוָה׃
אַל־תְּחַלֵּל אֶת־בִּתְּךָ לְהַזְנוֹתָהּ וְלֹא־תִזְנֶה הָאָרֶץ וּמָלְאָה הָאָרֶץ זִמָּה׃
אֶת־שַׁבְּתֹתַי תִּשְׁמֹרוּ וּמִקְדָּשִׁי תִּירָאוּ אֲנִי יְהוָה׃
אַל־תִּפְנוּ אֶל־הָאֹבֹת וְאֶל־הַיִּדְּעֹנִים אַל־תְּבַקְשׁוּ לְטָמְאָה בָהֶם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
מִפְּנֵי שֵׂיבָה תָּקוּם וְהָדַרְתָּ פְּנֵי זָקֵן וְיָרֵאתָ מֵּאֱלֹהֶיךָ אֲנִי יְהוָה׃
וְכִי־יָגוּר אִתְּךָ גֵּר בְּאַרְצְכֶם לֹא תוֹנוּ אֹתוֹ׃
כְּאֶזְרָח מִכֶּם יִהְיֶה לָכֶם הַגֵּר הַגָּר אִתְּכֶם וְאָהַבְתָּ לוֹ כָּמוֹךָ כִּי־גֵרִים הֱיִיתֶם בְּאֶרֶץ מִצְרָיִם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
לֹא־תַעֲשׂוּ עָוֶל בַּמִּשְׁפָּט בַּמִּדָּה בַּמִּשְׁקָל וּבַמְּשׂוּרָה׃
מֹאזְנֵי צֶדֶק אַבְנֵי־צֶדֶק אֵיפַת צֶדֶק וְהִין צֶדֶק יִהְיֶה לָכֶם אֲנִי יְהוָה אֱלֹהֵיכֶם אֲשֶׁר־הוֹצֵאתִי אֶתְכֶם מֵאֶרֶץ מִצְרָיִם׃
וּשְׁמַרְתֶּם אֶת־כָּל־חֻקֹּתַי וְאֶת־כָּל־מִשְׁפָּטַי וַעֲשִׂיתֶם אֹתָם אֲנִי יְהוָה׃

Chapter 20

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
וְאֶל־בְּנֵי יִשְׂרָאֵל תֹּאמַר אִישׁ אִישׁ מִבְּנֵי יִשְׂרָאֵל וּמִן־הַגֵּר הַגָּר בְּיִשְׂרָאֵל אֲשֶׁר יִתֵּן מִזַּרְעוֹ לַמֹּלֶךְ מוֹת יוּמָת עַם הָאָרֶץ יִרְגְּמֻהוּ בָאָבֶן׃
וַאֲנִי אֶתֵּן אֶת־פָּנַי בָּאִישׁ הַהוּא וְהִכְרַתִּי אֹתוֹ מִקֶּרֶב עַמּוֹ כִּי מִזַּרְעוֹ נָתַן לַמֹּלֶךְ לְמַעַן טַמֵּא אֶת־מִקְדָּשִׁי וּלְחַלֵּל אֶת־שֵׁם קָדְשִׁי׃
וְאִם הַעְלֵם יַעְלִימוּ עַם הָאָרֶץ אֶת־עֵינֵיהֶם מִן־הָאִישׁ הַהוּא בְּתִתּוֹ מִזַּרְעוֹ לַמֹּלֶךְ לְבִלְתִּי הָמִית אֹתוֹ׃
וְשַׂמְתִּי אֲנִי אֶת־פָּנַי בָּאִישׁ הַהוּא וּבְמִשְׁפַּחְתּוֹ וְהִכְרַתִּי אֹתוֹ וְאֵת כָּל־הַזֹּנִים אַחֲרָיו לִזְנוֹת אַחֲרֵי הַמֹּלֶךְ מִקֶּרֶב עַמָּם׃
וְהַנֶּפֶשׁ אֲשֶׁר תִּפְנֶה אֶל־הָאֹבֹת וְאֶל־הַיִּדְּעֹנִים לִזְנוֹת אַחֲרֵיהֶם וְנָתַתִּי אֶת־פָּנַי בַּנֶּפֶשׁ הַהִוא וְהִכְרַתִּי אֹתוֹ מִקֶּרֶב עַמּוֹ׃
וְהִתְקַדִּשְׁתֶּם וִהְיִיתֶם קְדֹשִׁים כִּי אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וּשְׁמַרְתֶּם אֶת־חֻקֹּתַי וַעֲשִׂיתֶם אֹתָם אֲנִי יְהוָה מְקַדִּשְׁכֶם׃
כִּי־אִישׁ אִישׁ אֲשֶׁר יְקַלֵּל אֶת־אָבִיו וְאֶת־אִמּוֹ מוֹת יוּמָת אָבִיו וְאִמּוֹ קִלֵּל דָּמָיו בּוֹ׃
וְאִישׁ אֲשֶׁר יִנְאַף אֶת־אֵשֶׁת אִישׁ אֲשֶׁר יִנְאַף אֶת־אֵשֶׁת רֵעֵהוּ מוֹת־יוּמַת הַנֹּאֵף וְהַנֹּאָפֶת׃
וְאִישׁ אֲשֶׁר יִשְׁכַּב אֶת־אֵשֶׁת אָבִיו עֶרְוַת אָבִיו גִּלָּה מוֹת־יוּמְתוּ שְׁנֵיהֶם דְּמֵיהֶם בָּם׃
וְאִישׁ אֲשֶׁר יִשְׁכַּב אֶת־כַּלָּתוֹ מוֹת יוּמְתוּ שְׁנֵיהֶם תֶּבֶל עָשׂוּ דְּמֵיהֶם בָּם׃
וְאִישׁ אֲשֶׁר יִשְׁכַּב אֶת־זָכָר מִשְׁכְּבֵי אִשָּׁה תּוֹעֵבָה עָשׂוּ שְׁנֵיהֶם מוֹת יוּמָתוּ דְּמֵיהֶם בָּם׃
וְאִישׁ אֲשֶׁר יִקַּח אֶת־אִשָּׁה וְאֶת־אִמָּהּ זִמָּה הִוא בָּאֵשׁ יִשְׂרְפוּ אֹתוֹ וְאֶתְהֶן וְלֹא־תִהְיֶה זִמָּה בְּתוֹכְכֶם׃
וְאִישׁ אֲשֶׁר יִתֵּן שְׁכָבְתּוֹ בִּבְהֵמָה מוֹת יוּמָת וְאֶת־הַבְּהֵמָה תַּהֲרֹגוּ׃
וְאִשָּׁה אֲשֶׁר תִּקְרַב אֶל־כָּל־בְּהֵמָה לְרִבְעָה אֹתָהּ וְהָרַגְתָּ אֶת־הָאִשָּׁה וְאֶת־הַבְּהֵמָה מוֹת יוּמָתוּ דְּמֵיהֶם בָּם׃
וְאִישׁ אֲשֶׁר־יִקַּח אֶת־אֲחֹתוֹ בַּת־אָבִיו אוֹ בַת־אִמּוֹ וְרָאָה אֶת־עֶרְוָתָהּ וְהִיא־תִרְאֶה אֶת־עֶרְוָתוֹ חֶסֶד הוּא וְנִכְרְתוּ לְעֵינֵי בְּנֵי עַמָּם עֶרְוַת אֲחֹתוֹ גִּלָּה עֲוֺנוֹ יִשָּׂא׃
וְאִישׁ אֲשֶׁר־יִשְׁכַּב אֶת־אִשָּׁה דָּוָה וְגִלָּה אֶת־עֶרְוָתָהּ אֶת־מְקֹרָהּ הֶעֱרָה וְהִיא גִּלְּתָה אֶת־מְקוֹר דָּמֶיהָ וְנִכְרְתוּ שְׁנֵיהֶם מִקֶּרֶב עַמָּם׃
וְעֶרְוַת אֲחוֹת אִמְּךָ וַאֲחוֹת אָבִיךָ לֹא תְגַלֵּה כִּי אֶת־שְׁאֵרוֹ הֶעֱרָה עֲוֺנָם יִשָּׂאוּ׃
וְאִישׁ אֲשֶׁר יִשְׁכַּב אֶת־דֹּדָתוֹ עֶרְוַת דֹּדוֹ גִּלָּה חֶטְאָם יִשָּׂאוּ עֲרִירִים יָמֻתוּ׃
וְאִישׁ אֲשֶׁר יִקַּח אֶת־אֵשֶׁת אָחִיו נִדָּה הִוא עֶרְוַת אָחִיו גִּלָּה עֲרִירִים יִהְיוּ׃
וּשְׁמַרְתֶּם אֶת־כָּל־חֻקֹּתַי וְאֶת־כָּל־מִשְׁפָּטַי וַעֲשִׂיתֶם אֹתָם וְלֹא־תָקִיא אֶתְכֶם הָאָרֶץ אֲשֶׁר אֲנִי מֵבִיא אֶתְכֶם שָׁמָּה לָשֶׁבֶת בָּהּ׃
וְלֹא תֵלְכוּ בְּחֻקֹּת הַגּוֹי אֲשֶׁר־אֲנִי מְשַׁלֵּחַ מִפְּנֵיכֶם כִּי אֶת־כָּל־אֵלֶּה עָשׂוּ וָאָקֻץ בָּם׃
וָאֹמַר לָכֶם אַתֶּם תִּירְשׁוּ אֶת־אַדְמָתָם וַאֲנִי אֶתְּנֶנָּה לָכֶם לָרֶשֶׁת אֹתָהּ אֶרֶץ זָבַת חָלָב וּדְבָשׁ אֲנִי יְהוָה אֱלֹהֵיכֶם אֲשֶׁר־הִבְדַּלְתִּי אֶתְכֶם מִן־הָעַמִּים׃
וְהִבְדַּלְתֶּם בֵּין־הַבְּהֵמָה הַטְּהֹרָה לַטְּמֵאָה וּבֵין־הָעוֹף הַטָּמֵא לַטָּהֹר וְלֹא־תְשַׁקְּצוּ אֶת־נַפְשֹׁתֵיכֶם בַּבְּהֵמָה וּבָעוֹף וּבְכֹל אֲשֶׁר תִּרְמֹשׂ הָאֲדָמָה אֲשֶׁר־הִבְדַּלְתִּי לָכֶם לְטַמֵּא׃
וִהְיִיתֶם לִי קְדֹשִׁים כִּי קָדוֹשׁ אֲנִי יְהוָה וָאַבְדִּל אֶתְכֶם מִן־הָעַמִּים לִהְיוֹת לִי׃
וְאִישׁ אוֹ־אִשָּׁה כִּי־יִהְיֶה בָהֶם אוֹב אוֹ יִדְּעֹנִי מוֹת יוּמָתוּ בָּאֶבֶן יִרְגְּמוּ אֹתָם דְּמֵיהֶם בָּם׃

Chapter 21

וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה אֱמֹר אֶל־הַכֹּהֲנִים בְּנֵי אַהֲרֹן וְאָמַרְתָּ אֲלֵהֶם לְנֶפֶשׁ לֹא־יִטַּמָּא בְּעַמָּיו׃
כִּי אִם־לִשְׁאֵרוֹ הַקָּרֹב אֵלָיו לְאִמּוֹ וּלְאָבִיו וְלִבְנוֹ וּלְבִתּוֹ וּלְאָחִיו׃
וְלַאֲחֹתוֹ הַבְּתוּלָה הַקְּרוֹבָה אֵלָיו אֲשֶׁר לֹא־הָיְתָה לְאִישׁ לָהּ יִטַּמָּא׃
לֹא יִטַּמָּא בַּעַל בְּעַמָּיו לְהֵחַלּוֹ׃
לֹא־יקרחה [יִקְרְחוּ] קָרְחָה בְּרֹאשָׁם וּפְאַת זְקָנָם לֹא יְגַלֵּחוּ וּבִבְשָׂרָם לֹא יִשְׂרְטוּ שָׂרָטֶת׃
קְדֹשִׁים יִהְיוּ לֵאלֹהֵיהֶם וְלֹא יְחַלְּלוּ שֵׁם אֱלֹהֵיהֶם כִּי אֶת־אִשֵּׁי יְהוָה לֶחֶם אֱלֹהֵיהֶם הֵם מַקְרִיבִם וְהָיוּ קֹדֶשׁ׃
אִשָּׁה זֹנָה וַחֲלָלָה לֹא יִקָּחוּ וְאִשָּׁה גְּרוּשָׁה מֵאִישָׁהּ לֹא יִקָּחוּ כִּי־קָדֹשׁ הוּא לֵאלֹהָיו׃
וְקִדַּשְׁתּוֹ כִּי־אֶת־לֶחֶם אֱלֹהֶיךָ הוּא מַקְרִיב קָדֹשׁ יִהְיֶה־לָּךְ כִּי קָדוֹשׁ אֲנִי יְהוָה מְקַדִּשְׁכֶם׃
וּבַת אִישׁ כֹּהֵן כִּי תֵחֵל לִזְנוֹת אֶת־אָבִיהָ הִיא מְחַלֶּלֶת בָּאֵשׁ תִּשָּׂרֵף׃
וְהַכֹּהֵן הַגָּדוֹל מֵאֶחָיו אֲ‍שֶׁר־יוּצַק עַל־רֹאשׁוֹ שֶׁמֶן הַמִּשְׁחָה וּמִלֵּא אֶת־יָדוֹ לִלְבֹּשׁ אֶת־הַבְּגָדִים אֶת־רֹאשׁוֹ לֹא יִפְרָע וּבְגָדָיו לֹא יִפְרֹם׃
וְעַל כָּל־נַפְשֹׁת מֵת לֹא יָבֹא לְאָבִיו וּלְאִמּוֹ לֹא יִטַּמָּא׃
וּמִן־הַמִּקְדָּשׁ לֹא יֵצֵא וְלֹא יְחַלֵּל אֵת מִקְדַּשׁ אֱלֹהָיו כִּי נֵזֶר שֶׁמֶן מִשְׁחַת אֱלֹהָיו עָלָיו אֲנִי יְהוָה׃
וְהוּא אִשָּׁה בִבְתוּלֶיהָ יִקָּח׃
אַלְמָנָה וּגְרוּשָׁה וַחֲלָלָה זֹנָה אֶת־אֵלֶּה לֹא יִקָּח כִּי אִם־בְּתוּלָה מֵעַמָּיו יִקַּח אִשָּׁה׃
וְלֹא־יְחַלֵּל זַרְעוֹ בְּעַמָּיו כִּי אֲנִי יְהוָה מְקַדְּשׁוֹ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־אַהֲרֹן לֵאמֹר אִישׁ מִזַּרְעֲךָ לְדֹרֹתָם אֲשֶׁר יִהְיֶה בוֹ מוּם לֹא יִקְרַב לְהַקְרִיב לֶחֶם אֱלֹהָיו׃
כִּי כָל־אִישׁ אֲשֶׁר־בּוֹ מוּם לֹא יִקְרָב אִישׁ עִוֵּר אוֹ פִסֵּחַ אוֹ חָרֻם אוֹ שָׂרוּעַ׃
אוֹ אִישׁ אֲשֶׁר־יִהְיֶה בוֹ שֶׁבֶר רָגֶל אוֹ שֶׁבֶר יָד׃
אוֹ־גִבֵּן אוֹ־דַק אוֹ תְּבַלֻּל בְּעֵינוֹ אוֹ גָרָב אוֹ יַלֶּפֶת אוֹ מְרוֹחַ אָשֶׁךְ׃
כָּל־אִישׁ אֲשֶׁר־בּוֹ מוּם מִזֶּרַע אַהֲרֹן הַכֹּהֵן לֹא יִגַּשׁ לְהַקְרִיב אֶת־אִשֵּׁי יְהוָה מוּם בּוֹ אֵת לֶחֶם אֱלֹהָיו לֹא יִגַּשׁ לְהַקְרִיב׃
לֶחֶם אֱלֹהָיו מִקָּדְשֵׁי הַקֳּדָשִׁים וּמִן־הַקֳּדָשִׁים יֹאכֵל׃
אַךְ אֶל־הַפָּרֹכֶת לֹא יָבֹא וְאֶל־הַמִּזְבֵּחַ לֹא יִגַּשׁ כִּי־מוּם בּוֹ וְלֹא יְחַלֵּל אֶת־מִקְדָּשַׁי כִּי אֲנִי יְהוָה מְקַדְּשָׁם׃
וַיְדַבֵּר מֹשֶׁה אֶל־אַהֲרֹן וְאֶל־בָּנָיו וְאֶל־כָּל־בְּנֵי יִשְׂרָאֵל׃

Chapter 22

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־אַהֲרֹן וְאֶל־בָּנָיו וְיִנָּזְרוּ מִקָּדְשֵׁי בְנֵי־יִשְׂרָאֵל וְלֹא יְחַלְּלוּ אֶת־שֵׁם קָדְשִׁי אֲשֶׁר הֵם מַקְדִּשִׁים לִי אֲנִי יְהוָה׃
אֱמֹר אֲלֵהֶם לְדֹרֹתֵיכֶם כָּל־אִישׁ אֲשֶׁר־יִקְרַב מִכָּל־זַרְעֲכֶם אֶל־הַקֳּדָשִׁים אֲשֶׁר יַקְדִּישׁוּ בְנֵי־יִשְׂרָאֵל לַיהוָה וְטֻמְאָתוֹ עָלָיו וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מִלְּפָנַי אֲנִי יְהוָה׃
אִישׁ אִישׁ מִזֶּרַע אַהֲרֹן וְהוּא צָרוּעַ אוֹ זָב בַּקֳּדָשִׁים לֹא יֹאכַל עַד אֲשֶׁר יִטְהָר וְהַנֹּגֵעַ בְּכָל־טְמֵא־נֶפֶשׁ אוֹ אִישׁ אֲשֶׁר־תֵּצֵא מִמֶּנּוּ שִׁכְבַת־זָרַע׃
אוֹ־אִישׁ אֲשֶׁר יִגַּע בְּכָל־שֶׁרֶץ אֲשֶׁר יִטְמָא־לוֹ אוֹ בְאָדָם אֲשֶׁר יִטְמָא־לוֹ לְכֹל טֻמְאָתוֹ׃
נֶפֶשׁ אֲשֶׁר תִּגַּע־בּוֹ וְטָמְאָה עַד־הָעָרֶב וְלֹא יֹאכַל מִן־הַקֳּדָשִׁים כִּי אִם־רָחַץ בְּשָׂרוֹ בַּמָּיִם׃
וּבָא הַשֶּׁמֶשׁ וְטָהֵר וְאַחַר יֹאכַל מִן־הַקֳּדָשִׁים כִּי לַחְמוֹ הוּא׃
נְבֵלָה וּטְרֵפָה לֹא יֹאכַל לְטָמְאָה־בָהּ אֲנִי יְהוָה׃
וְשָׁמְרוּ אֶת־מִשְׁמַרְתִּי וְלֹא־יִשְׂאוּ עָלָיו חֵטְא וּמֵתוּ בוֹ כִּי יְחַלְּלֻהוּ אֲנִי יְהוָה מְקַדְּשָׁם׃
וְכָל־זָר לֹא־יֹאכַל קֹדֶשׁ תּוֹשַׁב כֹּהֵן וְשָׂכִיר לֹא־יֹאכַל קֹדֶשׁ׃
וְכֹהֵן כִּי־יִקְנֶה נֶפֶשׁ קִנְיַן כַּסְפּוֹ הוּא יֹאכַל בּוֹ וִילִיד בֵּיתוֹ הֵם יֹאכְלוּ בְלַחְמוֹ׃
וּבַת־כֹּהֵן כִּי תִהְיֶה לְאִישׁ זָר הִוא בִּתְרוּמַת הַקֳּדָשִׁים לֹא תֹאכֵל׃
וּבַת־כֹּהֵן כִּי תִהְיֶה אַלְמָנָה וּגְרוּשָׁה וְזֶרַע אֵין לָהּ וְשָׁבָה אֶל־בֵּית אָבִיהָ כִּנְעוּרֶיהָ מִלֶּחֶם אָבִיהָ תֹּאכֵל וְכָל־זָר לֹא־יֹאכַל בּוֹ׃
וְאִישׁ כִּי־יֹאכַל קֹדֶשׁ בִּשְׁגָגָה וְיָסַף חֲמִשִׁיתוֹ עָלָיו וְנָתַן לַכֹּהֵן אֶת־הַקֹּדֶשׁ׃
וְלֹא יְחַלְּלוּ אֶת־קָדְשֵׁי בְּנֵי יִשְׂרָאֵל אֵת אֲשֶׁר־יָרִימוּ לַיהוָה׃
וְהִשִּׂיאוּ אוֹתָם עֲוֺן אַשְׁמָה בְּאָכְלָם אֶת־קָדְשֵׁיהֶם כִּי אֲנִי יְהוָה מְקַדְּשָׁם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־אַהֲרֹן וְאֶל־בָּנָיו וְאֶל כָּל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם אִישׁ אִישׁ מִבֵּית יִשְׂרָאֵל וּמִן־הַגֵּר בְּיִשְׂרָאֵל אֲשֶׁר יַקְרִיב קָרְבָּנוֹ לְכָל־נִדְרֵיהֶם וּלְכָל־נִדְבוֹתָם אֲשֶׁר־יַקְרִיבוּ לַיהוָה לְעֹלָה׃
לִרְצֹנְכֶם תָּמִים זָכָר בַּבָּקָר בַּכְּשָׂבִים וּבָעִזִּים׃
כֹּל אֲשֶׁר־בּוֹ מוּם לֹא תַקְרִיבוּ כִּי־לֹא לְרָצוֹן יִהְיֶה לָכֶם׃
וְאִישׁ כִּי־יַקְרִיב זֶבַח־שְׁלָמִים לַיהוָה לְפַלֵּא־נֶדֶר אוֹ לִנְדָבָה בַּבָּקָר אוֹ בַצֹּאן תָּמִים יִהְיֶה לְרָצוֹן כָּל־מוּם לֹא יִהְיֶה־בּוֹ׃
עַוֶּרֶת אוֹ שָׁבוּר אוֹ־חָרוּץ אוֹ־יַבֶּלֶת אוֹ גָרָב אוֹ יַלֶּפֶת לֹא־תַקְרִיבוּ אֵלֶּה לַיהוָה וְאִשֶּׁה לֹא־תִתְּנוּ מֵהֶם עַל־הַמִּזְבֵּחַ לַיהוָה׃
וְשׁוֹר וָשֶׂה שָׂרוּעַ וְקָלוּט נְדָבָה תַּעֲשֶׂה אֹתוֹ וּלְנֵדֶר לֹא יֵרָצֶה׃
וּמָעוּךְ וְכָתוּת וְנָתוּק וְכָרוּת לֹא תַקְרִיבוּ לַיהוָה וּבְאַרְצְכֶם לֹא תַעֲשׂוּ׃
וּמִיַּד בֶּן־נֵכָר לֹא תַקְרִיבוּ אֶת־לֶחֶם אֱלֹהֵיכֶם מִכָּל־אֵלֶּה כִּי מָשְׁחָתָם בָּהֶם מוּם בָּם לֹא יֵרָצוּ לָכֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
שׁוֹר אוֹ־כֶשֶׂב אוֹ־עֵז כִּי יִוָּלֵד וְהָיָה שִׁבְעַת יָמִים תַּחַת אִמּוֹ וּמִיּוֹם הַשְּׁמִינִי וָהָלְאָה יֵרָצֶה לְקָרְבַּן אִשֶּׁה לַיהוָה׃
וְשׁוֹר אוֹ־שֶׂה אֹתוֹ וְאֶת־בְּנוֹ לֹא תִשְׁחֲטוּ בְּיוֹם אֶחָד׃
וְכִי־תִזְבְּחוּ זֶבַח־תּוֹדָה לַיהוָה לִרְצֹנְכֶם תִּזְבָּחוּ׃
בַּיּוֹם הַהוּא יֵאָכֵל לֹא־תוֹתִירוּ מִמֶּנּוּ עַד־בֹּקֶר אֲנִי יְהוָה׃
וּשְׁמַרְתֶּם מִצְוֺתַי וַעֲשִׂיתֶם אֹתָם אֲנִי יְהוָה׃
וְלֹא תְחַלְּלוּ אֶת־שֵׁם קָדְשִׁי וְנִקְדַּשְׁתִּי בְּתוֹךְ בְּנֵי יִשְׂרָאֵל אֲנִי יְהוָה מְקַדִּשְׁכֶם׃
הַמּוֹצִיא אֶתְכֶם מֵאֶרֶץ מִצְרַיִם לִהְיוֹת לָכֶם לֵאלֹהִים אֲנִי יְהוָה׃

Chapter 23

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם מוֹעֲדֵי יְהוָה אֲשֶׁר־תִּקְרְאוּ אֹתָם מִקְרָאֵי קֹדֶשׁ אֵלֶּה הֵם מוֹעֲדָי׃
שֵׁשֶׁת יָמִים תֵּעָשֶׂה מְלָאכָה וּבַיּוֹם הַשְּׁבִיעִי שַׁבַּת שַׁבָּתוֹן מִקְרָא־קֹדֶשׁ כָּל־מְלָאכָה לֹא תַעֲשׂוּ שַׁבָּת הִוא לַיהוָה בְּכֹל מוֹשְׁבֹתֵיכֶם׃
אֵלֶּה מוֹעֲדֵי יְהוָה מִקְרָאֵי קֹדֶשׁ אֲשֶׁר־תִּקְרְאוּ אֹתָם בְּמוֹעֲדָם׃
בַּחֹדֶשׁ הָרִאשׁוֹן בְּאַרְבָּעָה עָשָׂר לַחֹדֶשׁ בֵּין הָעַרְבָּיִם פֶּסַח לַיהוָה׃
וּבַחֲמִשָּׁה עָשָׂר יוֹם לַחֹדֶשׁ הַזֶּה חַג הַמַּצּוֹת לַיהוָה שִׁבְעַת יָמִים מַצּוֹת תֹּאכֵלוּ׃
בַּיּוֹם הָרִאשׁוֹן מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
וְהִקְרַבְתֶּם אִשֶּׁה לַיהוָה שִׁבְעַת יָמִים בַּיּוֹם הַשְּׁבִיעִי מִקְרָא־קֹדֶשׁ כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם כִּי־תָבֹאוּ אֶל־הָאָרֶץ אֲשֶׁר אֲנִי נֹתֵן לָכֶם וּקְצַרְתֶּם אֶת־קְצִירָהּ וַהֲבֵאתֶם אֶת־עֹמֶר רֵאשִׁית קְצִירְכֶם אֶל־הַכֹּהֵן׃
וְהֵנִיף אֶת־הָעֹמֶר לִפְנֵי יְהוָה לִרְצֹנְכֶם מִמָּחֳרַת הַשַּׁבָּת יְנִיפֶנּוּ הַכֹּהֵן׃
וַעֲשִׂיתֶם בְּיוֹם הֲנִיפְכֶם אֶת־הָעֹמֶר כֶּבֶשׂ תָּמִים בֶּן־שְׁנָתוֹ לְעֹלָה לַיהוָה׃
וּמִנְחָתוֹ שְׁנֵי עֶשְׂרֹנִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן אִשֶּׁה לַיהוָה רֵיחַ נִיחֹחַ וְנִסְכֹּה יַיִן רְבִיעִת הַהִין׃
וְלֶחֶם וְקָלִי וְכַרְמֶל לֹא תֹאכְלוּ עַד־עֶצֶם הַיּוֹם הַזֶּה עַד הֲבִיאֲכֶם אֶת־קָרְבַּן אֱלֹהֵיכֶם חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם בְּכֹל מֹשְׁבֹתֵיכֶם׃
וּסְפַרְתֶּם לָכֶם מִמָּחֳרַת הַשַּׁבָּת מִיּוֹם הֲבִיאֲכֶם אֶת־עֹמֶר הַתְּנוּפָה שֶׁבַע שַׁבָּתוֹת תְּמִימֹת תִּהְיֶינָה׃
עַד מִמָּחֳרַת הַשַּׁבָּת הַשְּׁבִיעִת תִּסְפְּרוּ חֲמִשִּׁים יוֹם וְהִקְרַבְתֶּם מִנְחָה חֲדָשָׁה לַיהוָה׃
מִמּוֹשְׁבֹתֵיכֶם תָּבִיאּוּ לֶחֶם תְּנוּפָה שְׁתַּיִם שְׁנֵי עֶשְׂרֹנִים סֹלֶת תִּהְיֶינָה חָמֵץ תֵּאָפֶינָה בִּכּוּרִים לַיהוָה׃
וְהִקְרַבְתֶּם עַל־הַלֶּחֶם שִׁבְעַת כְּבָשִׂים תְּמִימִם בְּנֵי שָׁנָה וּפַר בֶּן־בָּקָר אֶחָד וְאֵילִם שְׁנָיִם יִהְיוּ עֹלָה לַיהוָה וּמִנְחָתָם וְנִסְכֵּיהֶם אִשֵּׁה רֵיחַ־נִיחֹחַ לַיהוָה׃
וַעֲשִׂיתֶם שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת וּשְׁנֵי כְבָשִׂים בְּנֵי שָׁנָה לְזֶבַח שְׁלָמִים׃
וְהֵנִיף הַכֹּהֵן אֹתָם עַל לֶחֶם הַבִּכּוּרִים תְּנוּפָה לִפְנֵי יְהוָה עַל־שְׁנֵי כְּבָשִׂים קֹדֶשׁ יִהְיוּ לַיהוָה לַכֹּהֵן׃
וּקְרָאתֶם בְּעֶצֶם הַיּוֹם הַזֶּה מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ חֻקַּת עוֹלָם בְּכָל־מוֹשְׁבֹתֵיכֶם לְדֹרֹתֵיכֶם׃
וּבְקֻצְרְכֶם אֶת־קְצִיר אַרְצְכֶם לֹא־תְכַלֶּה פְּאַת שָׂדְךָ בְּקֻצְרֶךָ וְלֶקֶט קְצִירְךָ לֹא תְלַקֵּט לֶעָנִי וְלַגֵּר תַּעֲזֹב אֹתָם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר בַּחֹדֶשׁ הַשְּׁבִיעִי בְּאֶחָד לַחֹדֶשׁ יִהְיֶה לָכֶם שַׁבָּתוֹן זִכְרוֹן תְּרוּעָה מִקְרָא־קֹדֶשׁ׃
כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ וְהִקְרַבְתֶּם אִשֶּׁה לַיהוָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
אַךְ בֶּעָשׂוֹר לַחֹדֶשׁ הַשְּׁבִיעִי הַזֶּה יוֹם הַכִּפֻּרִים הוּא מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם וְעִנִּיתֶם אֶת־נַפְשֹׁתֵיכֶם וְהִקְרַבְתֶּם אִשֶּׁה לַיהוָה׃
וְכָל־מְלָאכָה לֹא תַעֲשׂוּ בְּעֶצֶם הַיּוֹם הַזֶּה כִּי יוֹם כִּפֻּרִים הוּא לְכַפֵּר עֲלֵיכֶם לִפְנֵי יְהוָה אֱלֹהֵיכֶם׃
כִּי כָל־הַנֶּפֶשׁ אֲשֶׁר לֹא־תְעֻנֶּה בְּעֶצֶם הַיּוֹם הַזֶּה וְנִכְרְתָה מֵעַמֶּיהָ׃
וְכָל־הַנֶּפֶשׁ אֲשֶׁר תַּעֲשֶׂה כָּל־מְלָאכָה בְּעֶצֶם הַיּוֹם הַזֶּה וְהַאֲבַדְתִּי אֶת־הַנֶּפֶשׁ הַהִוא מִקֶּרֶב עַמָּהּ׃
כָּל־מְלָאכָה לֹא תַעֲשׂוּ חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם בְּכֹל מֹשְׁבֹתֵיכֶם׃
שַׁבַּת שַׁבָּתוֹן הוּא לָכֶם וְעִנִּיתֶם אֶת־נַפְשֹׁתֵיכֶם בְּתִשְׁעָה לַחֹדֶשׁ בָּעֶרֶב מֵעֶרֶב עַד־עֶרֶב תִּשְׁבְּתוּ שַׁבַּתְּכֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר בַּחֲמִשָּׁה עָשָׂר יוֹם לַחֹדֶשׁ הַשְּׁבִיעִי הַזֶּה חַג הַסֻּכּוֹת שִׁבְעַת יָמִים לַיהֹוָה׃
בַּיּוֹם הָרִאשׁוֹן מִקְרָא־קֹדֶשׁ כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
שִׁבְעַת יָמִים תַּקְרִיבוּ אִשֶּׁה לַיהוָה בַּיּוֹם הַשְּׁמִינִי מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם וְהִקְרַבְתֶּם אִשֶּׁה לַיהוָה עֲצֶרֶת הִוא כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
אֵלֶּה מוֹעֲדֵי יְהוָה אֲשֶׁר־תִּקְרְאוּ אֹתָם מִקְרָאֵי קֹדֶשׁ לְהַקְרִיב אִשֶּׁה לַיהוָה עֹלָה וּמִנְחָה זֶבַח וּנְסָכִים דְּבַר־יוֹם בְּיוֹמוֹ׃
מִלְּבַד שַׁבְּתֹת יְּהוָה וּמִלְּבַד מַתְּנוֹתֵיכֶם וּמִלְּבַד כָּל־נִדְרֵיכֶם וּמִלְּבַד כָּל־נִדְבוֹתֵיכֶם אֲשֶׁר תִּתְּנוּ לַיהוָה׃
אַךְ בַּחֲמִשָּׁה עָשָׂר יוֹם לַחֹדֶשׁ הַשְּׁבִיעִי בְּאָסְפְּכֶם אֶת־תְּבוּאַת הָאָרֶץ תָּחֹגּוּ אֶת־חַג־יְהוָה שִׁבְעַת יָמִים בַּיּוֹם הָרִאשׁוֹן שַׁבָּתוֹן וּבַיּוֹם הַשְּׁמִינִי שַׁבָּתוֹן׃
וּלְקַחְתֶּם לָכֶם בַּיּוֹם הָרִאשׁוֹן פְּרִי עֵץ הָדָר כַּפֹּת תְּמָרִים וַעֲנַף עֵץ־עָבֹת וְעַרְבֵי־נָחַל וּשְׂמַחְתֶּם לִפְנֵי יְהוָה אֱלֹהֵיכֶם שִׁבְעַת יָמִים׃
וְחַגֹּתֶם אֹתוֹ חַג לַיהוָה שִׁבְעַת יָמִים בַּשָּׁנָה חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם בַּחֹדֶשׁ הַשְּׁבִיעִי תָּחֹגּוּ אֹתוֹ׃
בַּסֻּכֹּת תֵּשְׁבוּ שִׁבְעַת יָמִים כָּל־הָאֶזְרָח בְּיִשְׂרָאֵל יֵשְׁבוּ בַּסֻּכֹּת׃
לְמַעַן יֵדְעוּ דֹרֹתֵיכֶם כִּי בַסֻּכּוֹת הוֹשַׁבְתִּי אֶת־בְּנֵי יִשְׂרָאֵל בְּהוֹצִיאִי אוֹתָם מֵאֶרֶץ מִצְרָיִם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וַיְדַבֵּר מֹשֶׁה אֶת־מֹעֲדֵי יְהוָה אֶל־בְּנֵי יִשְׂרָאֵל׃

Chapter 24

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
צַו אֶת־בְּנֵי יִשְׂרָאֵל וְיִקְחוּ אֵלֶיךָ שֶׁמֶן זַיִת זָךְ כָּתִית לַמָּאוֹר לְהַעֲלֹת נֵר תָּמִיד׃
מִחוּץ לְפָרֹכֶת הָעֵדֻת בְּאֹהֶל מוֹעֵד יַעֲרֹךְ אֹתוֹ אַהֲרֹן מֵעֶרֶב עַד־בֹּקֶר לִפְנֵי יְהוָה תָּמִיד חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם׃
עַל הַמְּנֹרָה הַטְּהֹרָה יַעֲרֹךְ אֶת־הַנֵּרוֹת לִפְנֵי יְהוָה תָּמִיד׃
וְלָקַחְתָּ סֹלֶת וְאָפִיתָ אֹתָהּ שְׁתֵּים עֶשְׂרֵה חַלּוֹת שְׁנֵי עֶשְׂרֹנִים יִהְיֶה הַחַלָּה הָאֶחָת׃
וְשַׂמְתָּ אוֹתָם שְׁתַּיִם מַעֲרָכוֹת שֵׁשׁ הַמַּעֲרָכֶת עַל הַשֻּׁלְחָן הַטָּהֹר לִפְנֵי יְהוָה׃
וְנָתַתָּ עַל־הַמַּעֲרֶכֶת לְבֹנָה זַכָּה וְהָיְתָה לַלֶּחֶם לְאַזְכָּרָה אִשֶּׁה לַיהוָה׃
בְּיוֹם הַשַּׁבָּת בְּיוֹם הַשַּׁבָּת יַעַרְכֶנּוּ לִפְנֵי יְהוָה תָּמִיד מֵאֵת בְּנֵי־יִשְׂרָאֵל בְּרִית עוֹלָם׃
וְהָיְתָה לְאַהֲרֹן וּלְבָנָיו וַאֲכָלֻהוּ בְּמָקוֹם קָדֹשׁ כִּי קֹדֶשׁ קָדָשִׁים הוּא לוֹ מֵאִשֵּׁי יְהוָה חָק־עוֹלָם׃
וַיֵּצֵא בֶּן־אִשָּׁה יִשְׂרְאֵלִית וְהוּא בֶּן־אִישׁ מִצְרִי בְּתוֹךְ בְּנֵי יִשְׂרָאֵל וַיִּנָּצוּ בַּמַּחֲנֶה בֶּן הַיִּשְׂרְאֵלִית וְאִישׁ הַיִּשְׂרְאֵלִי׃
וַיִּקֹּב בֶּן־הָאִשָּׁה הַיִּשְׂרְאֵלִית אֶת־הַשֵּׁם וַיְקַלֵּל וַיָּבִיאוּ אֹתוֹ אֶל־מֹשֶׁה וְשֵׁם אִמּוֹ שְׁלֹמִית בַּת־דִּבְרִי לְמַטֵּה־דָן׃
וַיַּנִּיחֻהוּ בַּמִּשְׁמָר לִפְרֹשׁ לָהֶם עַל־פִּי יְהוָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
הוֹצֵא אֶת־הַמְקַלֵּל אֶל־מִחוּץ לַמַּחֲנֶה וְסָמְכוּ כָל־הַשֹּׁמְעִים אֶת־יְדֵיהֶם עַל־רֹאשׁוֹ וְרָגְמוּ אֹתוֹ כָּל־הָעֵדָה׃
וְאֶל־בְּנֵי יִשְׂרָאֵל תְּדַבֵּר לֵאמֹר אִישׁ אִישׁ כִּי־יְקַלֵּל אֱלֹהָיו וְנָשָׂא חֶטְאוֹ׃
וְנֹקֵב שֵׁם־יְהוָה מוֹת יוּמָת רָגוֹם יִרְגְּמוּ־בוֹ כָּל־הָעֵדָה כַּגֵּר כָּאֶזְרָח בְּנָקְבוֹ־שֵׁם יוּמָת׃
וְאִישׁ כִּי יַכֶּה כָּל־נֶפֶשׁ אָדָם מוֹת יוּמָת׃
וּמַכֵּה נֶפֶשׁ־בְּהֵמָה יְשַׁלְּמֶנָּה נֶפֶשׁ תַּחַת נָפֶשׁ׃
וְאִישׁ כִּי־יִתֵּן מוּם בַּעֲמִיתוֹ כַּאֲשֶׁר עָשָׂה כֵּן יֵעָשֶׂה לּוֹ׃
שֶׁבֶר תַּחַת שֶׁבֶר עַיִן תַּחַת עַיִן שֵׁן תַּחַת שֵׁן כַּאֲשֶׁר יִתֵּן מוּם בָּאָדָם כֵּן יִנָּתֶן בּוֹ׃
וּמַכֵּה בְהֵמָה יְשַׁלְּמֶנָּה וּמַכֵּה אָדָם יוּמָת׃
מִשְׁפַּט אֶחָד יִהְיֶה לָכֶם כַּגֵּר כָּאֶזְרָח יִהְיֶה כִּי אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וַיְדַבֵּר מֹשֶׁה אֶל־בְּנֵי יִשְׂרָאֵל וַיּוֹצִיאוּ אֶת־הַמְקַלֵּל אֶל־מִחוּץ לַמַּחֲנֶה וַיִּרְגְּמוּ אֹתוֹ אָבֶן וּבְנֵי־יִשְׂרָאֵל עָשׂוּ כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃

Chapter 25

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה בְּהַר סִינַי לֵאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם כִּי תָבֹאוּ אֶל־הָאָרֶץ אֲשֶׁר אֲנִי נֹתֵן לָכֶם וְשָׁבְתָה הָאָרֶץ שַׁבָּת לַיהוָה׃
שֵׁשׁ שָׁנִים תִּזְרַע שָׂדֶךָ וְשֵׁשׁ שָׁנִים תִּזְמֹר כַּרְמֶךָ וְאָסַפְתָּ אֶת־תְּבוּאָתָהּ׃
וּבַשָּׁנָה הַשְּׁבִיעִת שַׁבַּת שַׁבָּתוֹן יִהְיֶה לָאָרֶץ שַׁבָּת לַיהוָה שָׂדְךָ לֹא תִזְרָע וְכַרְמְךָ לֹא תִזְמֹר׃
אֵת סְפִיחַ קְצִירְךָ לֹא תִקְצוֹר וְאֶת־עִנְּבֵי נְזִירֶךָ לֹא תִבְצֹר שְׁנַת שַׁבָּתוֹן יִהְיֶה לָאָרֶץ׃
וְהָיְתָה שַׁבַּת הָאָרֶץ לָכֶם לְאָכְלָה לְךָ וּלְעַבְדְּךָ וְלַאֲמָתֶךָ וְלִשְׂכִירְךָ וּלְתוֹשָׁבְךָ הַגָּרִים עִמָּךְ׃
וְלִבְהֶמְתְּךָ וְלַחַיָּה אֲשֶׁר בְּאַרְצֶךָ תִּהְיֶה כָל־תְּבוּאָתָהּ לֶאֱכֹל׃
וְסָפַרְתָּ לְךָ שֶׁבַע שַׁבְּתֹת שָׁנִים שֶׁבַע שָׁנִים שֶׁבַע פְּעָמִים וְהָיוּ לְךָ יְמֵי שֶׁבַע שַׁבְּתֹת הַשָּׁנִים תֵּשַׁע וְאַרְבָּעִים שָׁנָה׃
וְהַעֲבַרְתָּ שׁוֹפַר תְּרוּעָה בַּחֹדֶשׁ הַשְּׁבִעִי בֶּעָשׂוֹר לַחֹדֶשׁ בְּיוֹם הַכִּפֻּרִים תַּעֲבִירוּ שׁוֹפָר בְּכָל־אַרְצְכֶם׃
וְקִדַּשְׁתֶּם אֵת שְׁנַת הַחֲמִשִּׁים שָׁנָה וּקְרָאתֶם דְּרוֹר בָּאָרֶץ לְכָל־יֹשְׁבֶיהָ יוֹבֵל הִוא תִּהְיֶה לָכֶם וְשַׁבְתֶּם אִישׁ אֶל־אֲחֻזָּתוֹ וְאִישׁ אֶל־מִשְׁפַּחְתּוֹ תָּשֻׁבוּ׃
יוֹבֵל הִוא שְׁנַת הַחֲמִשִּׁים שָׁנָה תִּהְיֶה לָכֶם לֹא תִזְרָעוּ וְלֹא תִקְצְרוּ אֶת־סְפִיחֶיהָ וְלֹא תִבְצְרוּ אֶת־נְזִרֶיהָ׃
כִּי יוֹבֵל הִוא קֹדֶשׁ תִּהְיֶה לָכֶם מִן־הַשָּׂדֶה תֹּאכְלוּ אֶת־תְּבוּאָתָהּ׃
בִּשְׁנַת הַיּוֹבֵל הַזֹּאת תָּשֻׁבוּ אִישׁ אֶל־אֲחֻזָּתוֹ׃
וְכִי־תִמְכְּרוּ מִמְכָּר לַעֲמִיתֶךָ אוֹ קָנֹה מִיַּד עֲמִיתֶךָ אַל־תּוֹנוּ אִישׁ אֶת־אָחִיו׃
בְּמִסְפַּר שָׁנִים אַחַר הַיּוֹבֵל תִּקְנֶה מֵאֵת עֲמִיתֶךָ בְּמִסְפַּר שְׁנֵי־תְבוּאֹת יִמְכָּר־לָךְ׃
לְפִי רֹב הַשָּׁנִים תַּרְבֶּה מִקְנָתוֹ וּלְפִי מְעֹט הַשָּׁנִים תַּמְעִיט מִקְנָתוֹ כִּי מִסְפַּר תְּבוּאֹת הוּא מֹכֵר לָךְ׃
וְלֹא תוֹנוּ אִישׁ אֶת־עֲמִיתוֹ וְיָרֵאתָ מֵאֱלֹהֶיךָ כִּי אֲנִי יְהֹוָה אֱלֹהֵיכֶם׃
וַעֲשִׂיתֶם אֶת־חֻקֹּתַי וְאֶת־מִשְׁפָּטַי תִּשְׁמְרוּ וַעֲשִׂיתֶם אֹתָם וִישַׁבְתֶּם עַל־הָאָרֶץ לָבֶטַח׃
וְנָתְנָה הָאָרֶץ פִּרְיָהּ וַאֲכַלְתֶּם לָשֹׂבַע וִישַׁבְתֶּם לָבֶטַח עָלֶיהָ׃
וְכִי תֹאמְרוּ מַה־נֹּאכַל בַּשָּׁנָה הַשְּׁבִיעִת הֵן לֹא נִזְרָע וְלֹא נֶאֱסֹף אֶת־תְּבוּאָתֵנוּ׃
וְצִוִּיתִי אֶת־בִּרְכָתִי לָכֶם בַּשָּׁנָה הַשִּׁשִּׁית וְעָשָׂת אֶת־הַתְּבוּאָה לִשְׁלֹשׁ הַשָּׁנִים׃
וּזְרַעְתֶּם אֵת הַשָּׁנָה הַשְּׁמִינִת וַאֲכַלְתֶּם מִן־הַתְּבוּאָה יָשָׁן עַד הַשָּׁנָה הַתְּשִׁיעִת עַד־בּוֹא תְּבוּאָתָהּ תֹּאכְלוּ יָשָׁן׃
וְהָאָרֶץ לֹא תִמָּכֵר לִצְמִתֻת כִּי־לִי הָאָרֶץ כִּי־גֵרִים וְתוֹשָׁבִים אַתֶּם עִמָּדִי׃
וּבְכֹל אֶרֶץ אֲחֻזַּתְכֶם גְּאֻלָּה תִּתְּנוּ לָאָרֶץ׃
כִּי־יָמוּךְ אָחִיךָ וּמָכַר מֵאֲחֻזָּתוֹ וּבָא גֹאֲלוֹ הַקָּרֹב אֵלָיו וְגָאַל אֵת מִמְכַּר אָחִיו׃
וְאִישׁ כִּי לֹא יִהְיֶה־לּוֹ גֹּאֵל וְהִשִּׂיגָה יָדוֹ וּמָצָא כְּדֵי גְאֻלָּתוֹ׃
וְחִשַּׁב אֶת־שְׁנֵי מִמְכָּרוֹ וְהֵשִׁיב אֶת־הָעֹדֵף לָאִישׁ אֲשֶׁר מָכַר־לוֹ וְשָׁב לַאֲחֻזָּתוֹ׃
וְאִם לֹא־מָצְאָה יָדוֹ דֵּי הָשִׁיב לוֹ וְהָיָה מִמְכָּרוֹ בְּיַד הַקֹּנֶה אֹתוֹ עַד שְׁנַת הַיּוֹבֵל וְיָצָא בַּיֹּבֵל וְשָׁב לַאֲחֻזָּתוֹ׃
וְאִישׁ כִּי־יִמְכֹּר בֵּית־מוֹשַׁב עִיר חוֹמָה וְהָיְתָה גְּאֻלָּתוֹ עַד־תֹּם שְׁנַת מִמְכָּרוֹ יָמִים תִּהְיֶה גְאֻלָּתוֹ׃
וְאִם לֹא־יִגָּאֵל עַד־מְלֹאת לוֹ שָׁנָה תְמִימָה וְקָם הַבַּיִת אֲשֶׁר־בָּעִיר אֲשֶׁר־לא [לוֹ] חֹמָה לַצְּמִיתֻת לַקֹּנֶה אֹתוֹ לְדֹרֹתָיו לֹא יֵצֵא בַּיֹּבֵל׃
וּבָתֵּי הַחֲצֵרִים אֲשֶׁר אֵין־לָהֶם חֹמָה סָבִיב עַל־שְׂדֵה הָאָרֶץ יֵחָשֵׁב גְּאֻלָּה תִּהְיֶה־לּוֹ וּבַיֹּבֵל יֵצֵא׃
וְעָרֵי הַלְוִיִּם בָּתֵּי עָרֵי אֲחֻזָּתָם גְּאֻלַּת עוֹלָם תִּהְיֶה לַלְוִיִּם׃
וַאֲשֶׁר יִגְאַל מִן־הַלְוִיִּם וְיָצָא מִמְכַּר־בַּיִת וְעִיר אֲחֻזָּתוֹ בַּיֹּבֵל כִּי בָתֵּי עָרֵי הַלְוִיִּם הִוא אֲחֻזָּתָם בְּתוֹךְ בְּנֵי יִשְׂרָאֵל׃
וּשְׂדֵה מִגְרַשׁ עָרֵיהֶם לֹא יִמָּכֵר כִּי־אֲחֻזַּת עוֹלָם הוּא לָהֶם׃
וְכִי־יָמוּךְ אָחִיךָ וּמָטָה יָדוֹ עִמָּךְ וְהֶחֱזַקְתָּ בּוֹ גֵּר וְתוֹשָׁב וָחַי עִמָּךְ׃
אַל־תִּקַּח מֵאִתּוֹ נֶשֶׁךְ וְתַרְבִּית וְיָרֵאתָ מֵאֱלֹהֶיךָ וְחֵי אָחִיךָ עִמָּךְ׃
אֶת־כַּסְפְּךָ לֹא־תִתֵּן לוֹ בְּנֶשֶׁךְ וּבְמַרְבִּית לֹא־תִתֵּן אָכְלֶךָ׃
אֲנִי יְהוָה אֱלֹהֵיכֶם אֲשֶׁר־הוֹצֵאתִי אֶתְכֶם מֵאֶרֶץ מִצְרָיִם לָתֵת לָכֶם אֶת־אֶרֶץ כְּנַעַן לִהְיוֹת לָכֶם לֵאלֹהִים׃
וְכִי־יָמוּךְ אָחִיךָ עִמָּךְ וְנִמְכַּר־לָךְ לֹא־תַעֲבֹד בּוֹ עֲבֹדַת עָבֶד׃
כְּשָׂכִיר כְּתוֹשָׁב יִהְיֶה עִמָּךְ עַד־שְׁנַת הַיֹּבֵל יַעֲבֹד עִמָּךְ׃
וְיָצָא מֵעִמָּךְ הוּא וּבָנָיו עִמּוֹ וְשָׁב אֶל־מִשְׁפַּחְתּוֹ וְאֶל־אֲחֻזַּת אֲבֹתָיו יָשׁוּב׃
כִּי־עֲבָדַי הֵם אֲשֶׁר־הוֹצֵאתִי אֹתָם מֵאֶרֶץ מִצְרָיִם לֹא יִמָּכְרוּ מִמְכֶּרֶת עָבֶד׃
לֹא־תִרְדֶּה בוֹ בְּפָרֶךְ וְיָרֵאתָ מֵאֱלֹהֶיךָ׃
וְעַבְדְּךָ וַאֲמָתְךָ אֲשֶׁר יִהְיוּ־לָךְ מֵאֵת הַגּוֹיִם אֲשֶׁר סְבִיבֹתֵיכֶם מֵהֶם תִּקְנוּ עֶבֶד וְאָמָה׃
וְגַם מִבְּנֵי הַתּוֹשָׁבִים הַגָּרִים עִמָּכֶם מֵהֶם תִּקְנוּ וּמִמִּשְׁפַּחְתָּם אֲשֶׁר עִמָּכֶם אֲשֶׁר הוֹלִידוּ בְּאַרְצְכֶם וְהָיוּ לָכֶם לַאֲחֻזָּה׃
וְהִתְנַחֲלְתֶּם אֹתָם לִבְנֵיכֶם אַחֲרֵיכֶם לָרֶשֶׁת אֲחֻזָּה לְעֹלָם בָּהֶם תַּעֲבֹדוּ וּבְאַחֵיכֶם בְּנֵי־יִשְׂרָאֵל אִישׁ בְּאָחִיו לֹא־תִרְדֶּה בוֹ בְּפָרֶךְ׃
וְכִי תַשִּׂיג יַד גֵּר וְתוֹשָׁב עִמָּךְ וּמָךְ אָחִיךָ עִמּוֹ וְנִמְכַּר לְגֵר תּוֹשָׁב עִמָּךְ אוֹ לְעֵקֶר מִשְׁפַּחַת גֵּר׃
אַחֲרֵי נִמְכַּר גְּאֻלָּה תִּהְיֶה־לּוֹ אֶחָד מֵאֶחָיו יִגְאָלֶנּוּ׃
אוֹ־דֹדוֹ אוֹ בֶן־דֹּדוֹ יִגְאָלֶנּוּ אוֹ־מִשְּׁאֵר בְּשָׂרוֹ מִמִּשְׁפַּחְתּוֹ יִגְאָלֶנּוּ אוֹ־הִשִּׂיגָה יָדוֹ וְנִגְאָל׃
וְחִשַּׁב עִם־קֹנֵהוּ מִשְּׁנַת הִמָּכְרוֹ לוֹ עַד שְׁנַת הַיֹּבֵל וְהָיָה כֶּסֶף מִמְכָּרוֹ בְּמִסְפַּר שָׁנִים כִּימֵי שָׂכִיר יִהְיֶה עִמּוֹ׃
אִם־עוֹד רַבּוֹת בַּשָּׁנִים לְפִיהֶן יָשִׁיב גְּאֻלָּתוֹ מִכֶּסֶף מִקְנָתוֹ׃
וְאִם־מְעַט נִשְׁאַר בַּשָּׁנִים עַד־שְׁנַת הַיֹּבֵל וְחִשַּׁב־לוֹ כְּפִי שָׁנָיו יָשִׁיב אֶת־גְּאֻלָּתוֹ׃
כִּשְׂכִיר שָׁנָה בְּשָׁנָה יִהְיֶה עִמּוֹ לֹא־יִרְדֶּנּוּ בְּפֶרֶךְ לְעֵינֶיךָ׃
וְאִם־לֹא יִגָּאֵל בְּאֵלֶּה וְיָצָא בִּשְׁנַת הַיֹּבֵל הוּא וּבָנָיו עִמּוֹ׃
כִּי־לִי בְנֵי־יִשְׂרָאֵל עֲבָדִים עֲבָדַי הֵם אֲשֶׁר־הוֹצֵאתִי אוֹתָם מֵאֶרֶץ מִצְרָיִם אֲנִי יְהוָה אֱלֹהֵיכֶם׃

Chapter 26

לֹא־תַעֲשׂוּ לָכֶם אֱלִילִם וּפֶסֶל וּמַצֵּבָה לֹא־תָקִימוּ לָכֶם וְאֶבֶן מַשְׂכִּית לֹא תִתְּנוּ בְּאַרְצְכֶם לְהִשְׁתַּחֲוֺת עָלֶיהָ כִּי אֲנִי יְהוָה אֱלֹהֵיכֶם׃
אֶת־שַׁבְּתֹתַי תִּשְׁמֹרוּ וּמִקְדָּשִׁי תִּירָאוּ אֲנִי יְהוָה׃
אִם־בְּחֻקֹּתַי תֵּלֵכוּ וְאֶת־מִצְוֺתַי תִּשְׁמְרוּ וַעֲשִׂיתֶם אֹתָם׃
וְנָתַתִּי גִשְׁמֵיכֶם בְּעִתָּם וְנָתְנָה הָאָרֶץ יְבוּלָהּ וְעֵץ הַשָּׂדֶה יִתֵּן פִּרְיוֹ׃
וְהִשִּׂיג לָכֶם דַּיִשׁ אֶת־בָּצִיר וּבָצִיר יַשִּׂיג אֶת־זָרַע וַאֲכַלְתֶּם לַחְמְכֶם לָשֹׂבַע וִישַׁבְתֶּם לָבֶטַח בְּאַרְצְכֶם׃
וְנָתַתִּי שָׁלוֹם בָּאָרֶץ וּשְׁכַבְתֶּם וְאֵין מַחֲרִיד וְהִשְׁבַּתִּי חַיָּה רָעָה מִן־הָאָרֶץ וְחֶרֶב לֹא־תַעֲבֹר בְּאַרְצְכֶם׃
וּרְדַפְתֶּם אֶת־אֹיְבֵיכֶם וְנָפְלוּ לִפְנֵיכֶם לֶחָרֶב
וְרָדְפוּ מִכֶּם חֲמִשָּׁה מֵאָה וּמֵאָה מִכֶּם רְבָבָה יִרְדֹּפוּ וְנָפְלוּ אֹיְבֵיכֶם לִפְנֵיכֶם לֶחָרֶב׃
וּפָנִיתִי אֲלֵיכֶם וְהִפְרֵיתִי אֶתְכֶם וְהִרְבֵּיתִי אֶתְכֶם וַהֲקִימֹתִי אֶת־בְּרִיתִי אִתְּכֶם׃
וַאֲכַלְתֶּם יָשָׁן נוֹשָׁן וְיָשָׁן מִפְּנֵי חָדָשׁ תּוֹצִיאוּ׃
וְנָתַתִּי מִשְׁכָּנִי בְּתוֹכְכֶם וְלֹא־תִגְעַל נַפְשִׁי אֶתְכֶם׃
וְהִתְהַלַּכְתִּי בְּתוֹכְכֶם וְהָיִיתִי לָכֶם לֵאלֹהִים וְאַתֶּם תִּהְיוּ־לִי לְעָם׃
אֲנִי יְהוָה אֱלֹהֵיכֶם אֲשֶׁר הוֹצֵאתִי אֶתְכֶם מֵאֶרֶץ מִצְרַיִם מִהְיֹת לָהֶם עֲבָדִים וָאֶשְׁבֹּר מֹטֹת עֻלְּכֶם וָאוֹלֵךְ אֶתְכֶם קוֹמְמִיּוּת׃
וְאִם־לֹא תִשְׁמְעוּ לִי וְלֹא תַעֲשׂוּ אֵת כָּל־הַמִּצְוֺת הָאֵלֶּה׃
וְאִם־בְּחֻקֹּתַי תִּמְאָסוּ וְאִם אֶת־מִשְׁפָּטַי תִּגְעַל נַפְשְׁכֶם לְבִלְתִּי עֲשׂוֹת אֶת־כָּל־מִצְוֺתַי לְהַפְרְכֶם אֶת־בְּרִיתִי׃
אַף־אֲנִי אֶעֱשֶׂה־זֹּאת לָכֶם וְהִפְקַדְתִּי עֲלֵיכֶם בֶּהָלָה אֶת־הַשַּׁחֶפֶת וְאֶת־הַקַּדַּחַת מְכַלּוֹת עֵינַיִם וּמְדִיבֹת נָפֶשׁ וּזְרַעְתֶּם לָרִיק זַרְעֲכֶם וַאֲכָלֻהוּ אֹיְבֵיכֶם׃
וְנָתַתִּי פָנַי בָּכֶם וְנִגַּפְתֶּם לִפְנֵי אֹיְבֵיכֶם וְרָדוּ בָכֶם שֹׂנְאֵיכֶם וְנַסְתֶּם וְאֵין־רֹדֵף אֶתְכֶם׃
וְאִם־עַד־אֵלֶּה לֹא תִשְׁמְעוּ לִי וְיָסַפְתִּי לְיַסְּרָה אֶתְכֶם שֶׁבַע עַל־חַטֹּאתֵיכֶם׃
וְשָׁבַרְתִּי אֶת־גְּאוֹן עֻזְּכֶם וְנָתַתִּי אֶת־שְׁמֵיכֶם כַּבַּרְזֶל וְאֶת־אַרְצְכֶם כַּנְּחֻשָׁה׃
וְתַם לָרִיק כֹּחֲכֶם וְלֹא־תִתֵּן אַרְצְכֶם אֶת־יְבוּלָהּ וְעֵץ הָאָרֶץ לֹא יִתֵּן פִּרְיוֹ׃
וְאִם־תֵּלְכוּ עִמִּי קֶרִי וְלֹא תֹאבוּ לִשְׁמֹעַ לִי וְיָסַפְתִּי עֲלֵיכֶם מַכָּה שֶׁבַע כְּחַטֹּאתֵיכֶם׃
וְהִשְׁלַחְתִּי בָכֶם אֶת־חַיַּת הַשָּׂדֶה וְשִׁכְּלָה אֶתְכֶם וְהִכְרִיתָה אֶת־בְּהֶמְתְּכֶם וְהִמְעִיטָה אֶתְכֶם וְנָשַׁמּוּ דַּרְכֵיכֶם׃
וְאִם־בְּאֵלֶּה לֹא תִוָּסְרוּ לִי וַהֲלַכְתֶּם עִמִּי קֶרִי׃
וְהָלַכְתִּי אַף־אֲנִי עִמָּכֶם בְּקֶרִי וְהִכֵּיתִי אֶתְכֶם גַּם־אָנִי שֶׁבַע עַל־חַטֹּאתֵיכֶם׃
וְהֵבֵאתִי עֲלֵיכֶם חֶרֶב נֹקֶמֶת נְקַם־בְּרִית וְנֶאֱסַפְתֶּם אֶל־עָרֵיכֶם וְשִׁלַּחְתִּי דֶבֶר בְּתוֹכְכֶם וְנִתַּתֶּם בְּיַד־אוֹיֵב׃
בְּשִׁבְרִי לָכֶם מַטֵּה־לֶחֶם וְאָפוּ עֶשֶׂר נָשִׁים לַחְמְכֶם בְּתַנּוּר אֶחָד וְהֵשִׁיבוּ לַחְמְכֶם בַּמִּשְׁקָל וַאֲכַלְתֶּם וְלֹא תִשְׂבָּעוּ׃
וְאִם־בְּזֹאת לֹא תִשְׁמְעוּ לִי וַהֲלַכְתֶּם עִמִּי בְּקֶרִי׃
וְהָלַכְתִּי עִמָּכֶם בַּחֲמַת־קֶרִי וְיִסַּרְתִּי אֶתְכֶם אַף־אָנִי שֶׁבַע עַל־חַטֹּאתֵיכֶם׃
וַאֲכַלְתֶּם בְּשַׂר בְּנֵיכֶם וּבְשַׂר בְּנֹתֵיכֶם תֹּאכֵלוּ׃
וְהִשְׁמַדְתִּי אֶת־בָּמֹתֵיכֶם וְהִכְרַתִּי אֶת־חַמָּנֵיכֶם וְנָתַתִּי אֶת־פִּגְרֵיכֶם עַל־פִּגְרֵי גִּלּוּלֵיכֶם וְגָעֲלָה נַפְשִׁי אֶתְכֶם׃
וְנָתַתִּי אֶת־עָרֵיכֶם חָרְבָּה וַהֲשִׁמּוֹתִי אֶת־מִקְדְּשֵׁיכֶם וְלֹא אָרִיחַ בְּרֵיחַ נִיחֹחֲכֶם׃
וַהֲשִׁמֹּתִי אֲנִי אֶת־הָאָרֶץ וְשָׁמְמוּ עָלֶיהָ אֹיְבֵיכֶם הַיֹּשְׁבִים בָּהּ׃
וְאֶתְכֶם אֱזָרֶה בַגּוֹיִם וַהֲרִיקֹתִי אַחֲרֵיכֶם חָרֶב וְהָיְתָה אַרְצְכֶם שְׁמָמָה וְעָרֵיכֶם יִהְיוּ חָרְבָּה׃
אָז תִּרְצֶה הָאָרֶץ אֶת־שַׁבְּתֹתֶיהָ כֹּל יְמֵי הֳשַׁמָּה וְאַתֶּם בְּאֶרֶץ אֹיְבֵיכֶם אָז תִּשְׁבַּת הָאָרֶץ וְהִרְצָת אֶת־שַׁבְּתֹתֶיהָ׃
כָּל־יְמֵי הָשַּׁמָּה תִּשְׁבֹּת אֵת אֲשֶׁר לֹא־שָׁבְתָה בְּשַׁבְּתֹתֵיכֶם בְּשִׁבְתְּכֶם עָלֶיהָ׃
וְהַנִּשְׁאָרִים בָּכֶם וְהֵבֵאתִי מֹרֶךְ בִּלְבָבָם בְּאַרְצֹת אֹיְבֵיהֶם וְרָדַף אֹתָם קוֹל עָלֶה נִדָּף וְנָסוּ מְנֻסַת־חֶרֶב וְנָפְלוּ וְאֵין רֹדֵף׃
וְכָשְׁלוּ אִישׁ־בְּאָחִיו כְּמִפְּנֵי־חֶרֶב וְרֹדֵף אָיִן וְלֹא־תִהְיֶה לָכֶם תְּקוּמָה לִפְנֵי אֹיְבֵיכֶם׃
וַאֲבַדְתֶּם בַּגּוֹיִם וְאָכְלָה אֶתְכֶם אֶרֶץ אֹיְבֵיכֶם׃
וְהַנִּשְׁאָרִים בָּכֶם יִמַּקּוּ בַּעֲוֺנָם בְּאַרְצֹת אֹיְבֵיכֶם וְאַף בַּעֲוֺנֹת אֲבֹתָם אִתָּם יִמָּקּוּ׃
וְהִתְוַדּוּ אֶת־עֲוֺנָם וְאֶת־עֲוֺן אֲבֹתָם בְּמַעֲלָם אֲשֶׁר מָעֲלוּ־בִי וְאַף אֲשֶׁר־הָלְכוּ עִמִּי בְּקֶרִי׃
אַף־אֲנִי אֵלֵךְ עִמָּם בְּקֶרִי וְהֵבֵאתִי אֹתָם בְּאֶרֶץ אֹיְבֵיהֶם אוֹ־אָז יִכָּנַע לְבָבָם הֶעָרֵל וְאָז יִרְצוּ אֶת־עֲוֺנָם׃
וְזָכַרְתִּי אֶת־בְּרִיתִי יַעֲקוֹב וְאַף אֶת־בְּרִיתִי יִצְחָק וְאַף אֶת־בְּרִיתִי אַבְרָהָם אֶזְכֹּר וְהָאָרֶץ אֶזְכֹּר׃
וְהָאָרֶץ תֵּעָזֵב מֵהֶם וְתִרֶץ אֶת־שַׁבְּתֹתֶיהָ בָּהְשַׁמָּה מֵהֶם וְהֵם יִרְצוּ אֶת־עֲוֺנָם יַעַן וּבְיַעַן בְּמִשְׁפָּטַי מָאָסוּ וְאֶת־חֻקֹּתַי גָּעֲלָה נַפְשָׁם׃
וְאַף־גַּם־זֹאת בִּהְיוֹתָם בְּאֶרֶץ אֹיְבֵיהֶם לֹא־מְאַסְתִּים וְלֹא־גְעַלְתִּים לְכַלֹּתָם לְהָפֵר בְּרִיתִי אִתָּם כִּי אֲנִי יְהוָה אֱלֹהֵיהֶם׃
וְזָכַרְתִּי לָהֶם בְּרִית רִאשֹׁנִים אֲשֶׁר הוֹצֵאתִי־אֹתָם מֵאֶרֶץ מִצְרַיִם לְעֵינֵי הַגּוֹיִם לִהְיֹת לָהֶם לֵאלֹהִים אֲנִי יְהוָה׃
אֵלֶּה הַחֻקִּים וְהַמִּשְׁפָּטִים וְהַתּוֹרֹת אֲשֶׁר נָתַן יְהוָה בֵּינוֹ וּבֵין בְּנֵי יִשְׂרָאֵל בְּהַר סִינַי בְּיַד־מֹשֶׁה׃

Chapter 27

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם אִישׁ כִּי יַפְלִא נֶדֶר בְּעֶרְכְּךָ נְפָשֹׁת לַיהוָה׃
וְהָיָה עֶרְכְּךָ הַזָּכָר מִבֶּן עֶשְׂרִים שָׁנָה וְעַד בֶּן־שִׁשִּׁים שָׁנָה וְהָיָה עֶרְכְּךָ חֲמִשִּׁים שֶׁקֶל כֶּסֶף בְּשֶׁקֶל הַקֹּדֶשׁ׃
וְאִם־נְקֵבָה הִוא וְהָיָה עֶרְכְּךָ שְׁלֹשִׁים שָׁקֶל׃
וְאִם מִבֶּן־חָמֵשׁ שָׁנִים וְעַד בֶּן־עֶשְׂרִים שָׁנָה וְהָיָה עֶרְכְּךָ הַזָּכָר עֶשְׂרִים שְׁקָלִים וְלַנְּקֵבָה עֲשֶׂרֶת שְׁקָלִים׃
וְאִם מִבֶּן־חֹדֶשׁ וְעַד בֶּן־חָמֵשׁ שָׁנִים וְהָיָה עֶרְכְּךָ הַזָּכָר חֲמִשָּׁה שְׁקָלִים כָּסֶף וְלַנְּקֵבָה עֶרְכְּךָ שְׁלֹשֶׁת שְׁקָלִים כָּסֶף׃
וְאִם מִבֶּן־שִׁשִּׁים שָׁנָה וָמַעְלָה אִם־זָכָר וְהָיָה עֶרְכְּךָ חֲמִשָּׁה עָשָׂר שָׁקֶל וְלַנְּקֵבָה עֲשָׂרָה שְׁקָלִים׃
וְאִם־מָךְ הוּא מֵעֶרְכֶּךָ וְהֶעֱמִידוֹ לִפְנֵי הַכֹּהֵן וְהֶעֱרִיךְ אֹתוֹ הַכֹּהֵן עַל־פִּי אֲשֶׁר תַּשִּׂיג יַד הַנֹּדֵר יַעֲרִיכֶנּוּ הַכֹּהֵן׃
וְאִם־בְּהֵמָה אֲשֶׁר יַקְרִיבוּ מִמֶּנָּה קָרְבָּן לַיהוָה כֹּל אֲשֶׁר יִתֵּן מִמֶּנּוּ לַיהוָה יִהְיֶה־קֹּדֶשׁ׃
לֹא יַחֲלִיפֶנּוּ וְלֹא־יָמִיר אֹתוֹ טוֹב בְּרָע אוֹ־רַע בְּטוֹב וְאִם־הָמֵר יָמִיר בְּהֵמָה בִּבְהֵמָה וְהָיָה־הוּא וּתְמוּרָתוֹ יִהְיֶה־קֹּדֶשׁ׃
וְאִם כָּל־בְּהֵמָה טְמֵאָה אֲשֶׁר לֹא־יַקְרִיבוּ מִמֶּנָּה קָרְבָּן לַיהוָה וְהֶעֱמִיד אֶת־הַבְּהֵמָה לִפְנֵי הַכֹּהֵן׃
וְהֶעֱרִיךְ הַכֹּהֵן אֹתָהּ בֵּין טוֹב וּבֵין רָע כְּעֶרְכְּךָ הַכֹּהֵן כֵּן יִהְיֶה׃
וְאִם־גָּאֹל יִגְאָלֶנָּה וְיָסַף חֲמִישִׁתוֹ עַל־עֶרְכֶּךָ׃
וְאִישׁ כִּי־יַקְדִּשׁ אֶת־בֵּיתוֹ קֹדֶשׁ לַיהוָה וְהֶעֱרִיכוֹ הַכֹּהֵן בֵּין טוֹב וּבֵין רָע כַּאֲשֶׁר יַעֲרִיךְ אֹתוֹ הַכֹּהֵן כֵּן יָקוּם׃
וְאִם־הַמַּקְדִּישׁ יִגְאַל אֶת־בֵּיתוֹ וְיָסַף חֲמִישִׁית כֶּסֶף־עֶרְכְּךָ עָלָיו וְהָיָה לוֹ׃
וְאִם מִשְּׂדֵה אֲחֻזָּתוֹ יַקְדִּישׁ אִישׁ לַיהוָה וְהָיָה עֶרְכְּךָ לְפִי זַרְעוֹ זֶרַע חֹמֶר שְׂעֹרִים בַּחֲמִשִּׁים שֶׁקֶל כָּסֶף׃
אִם־מִשְּׁנַת הַיֹּבֵל יַקְדִּישׁ שָׂדֵהוּ כְּעֶרְכְּךָ יָקוּם׃
וְאִם־אַחַר הַיֹּבֵל יַקְדִּישׁ שָׂדֵהוּ וְחִשַּׁב־לוֹ הַכֹּהֵן אֶת־הַכֶּסֶף עַל־פִּי הַשָּׁנִים הַנּוֹתָרֹת עַד שְׁנַת הַיֹּבֵל וְנִגְרַע מֵעֶרְכֶּךָ׃
וְאִם־גָּאֹל יִגְאַל אֶת־הַשָּׂדֶה הַמַּקְדִּישׁ אֹתוֹ וְיָסַף חֲמִשִׁית כֶּסֶף־עֶרְכְּךָ עָלָיו וְקָם לוֹ׃
וְאִם־לֹא יִגְאַל אֶת־הַשָּׂדֶה וְאִם־מָכַר אֶת־הַשָּׂדֶה לְאִישׁ אַחֵר לֹא יִגָּאֵל עוֹד׃
וְהָיָה הַשָּׂדֶה בְּצֵאתוֹ בַיֹּבֵל קֹדֶשׁ לַיהוָה כִּשְׂדֵה הַחֵרֶם לַכֹּהֵן תִּהְיֶה אֲחֻזָּתוֹ׃
וְאִם אֶת־שְׂדֵה מִקְנָתוֹ אֲשֶׁר לֹא מִשְּׂדֵה אֲחֻזָּתוֹ יַקְדִּישׁ לַיהוָה׃
וְחִשַּׁב־לוֹ הַכֹּהֵן אֵת מִכְסַת הָעֶרְכְּךָ עַד שְׁנַת הַיֹּבֵל וְנָתַן אֶת־הָעֶרְכְּךָ בַּיּוֹם הַהוּא קֹדֶשׁ לַיהוָה׃
בִּשְׁנַת הַיּוֹבֵל יָשׁוּב הַשָּׂדֶה לַאֲשֶׁר קָנָהוּ מֵאִתּוֹ לַאֲשֶׁר־לוֹ אֲחֻזַּת הָאָרֶץ׃
וְכָל־עֶרְכְּךָ יִהְיֶה בְּשֶׁקֶל הַקֹּדֶשׁ עֶשְׂרִים גֵּרָה יִהְיֶה הַשָּׁקֶל׃
אַךְ־בְּכוֹר אֲשֶׁר־יְבֻכַּר לַיהוָה בִּבְהֵמָה לֹא־יַקְדִּישׁ אִישׁ אֹתוֹ אִם־שׁוֹר אִם־שֶׂה לַיהוָה הוּא׃
וְאִם בַּבְּהֵמָה הַטְּמֵאָה וּפָדָה בְעֶרְכֶּךָ וְיָסַף חֲמִשִׁתוֹ עָלָיו וְאִם־לֹא יִגָּאֵל וְנִמְכַּר בְּעֶרְכֶּךָ׃
אַךְ־כָּל־חֵרֶם אֲשֶׁר יַחֲרִם אִישׁ לַיהוָה מִכָּל־אֲשֶׁר־לוֹ מֵאָדָם וּבְהֵמָה וּמִשְּׂדֵה אֲחֻזָּתוֹ לֹא יִמָּכֵר וְלֹא יִגָּאֵל כָּל־חֵרֶם קֹדֶשׁ־קָדָשִׁים הוּא לַיהוָה׃
כָּל־חֵרֶם אֲשֶׁר יָחֳרַם מִן־הָאָדָם לֹא יִפָּדֶה מוֹת יוּמָת׃
וְכָל־מַעְשַׂר הָאָרֶץ מִזֶּרַע הָאָרֶץ מִפְּרִי הָעֵץ לַיהוָה הוּא קֹדֶשׁ לַיהוָה׃
וְאִם־גָּאֹל יִגְאַל אִישׁ מִמַּעַשְׂרוֹ חֲמִשִׁיתוֹ יֹסֵף עָלָיו׃
וְכָל־מַעְשַׂר בָּקָר וָצֹאן כֹּל אֲשֶׁר־יַעֲבֹר תַּחַת הַשָּׁבֶט הָעֲשִׂירִי יִהְיֶה־קֹּדֶשׁ לַיהוָה׃
לֹא יְבַקֵּר בֵּין־טוֹב לָרַע וְלֹא יְמִירֶנּוּ וְאִם־הָמֵר יְמִירֶנּוּ וְהָיָה־הוּא וּתְמוּרָתוֹ יִהְיֶה־קֹדֶשׁ לֹא יִגָּאֵל׃
אֵלֶּה הַמִּצְוֺת אֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה אֶל־בְּנֵי יִשְׂרָאֵל בְּהַר סִינָי׃

============================================================
### Numbers  (/)
============================================================

Numbers
במדבר
Tanach with Nikkud
http://www.tanach.us/Tanach.xml

במדבר



Chapter 1

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה בְּמִדְבַּר סִינַי בְּאֹהֶל מוֹעֵד בְּאֶחָד לַחֹדֶשׁ הַשֵּׁנִי בַּשָּׁנָה הַשֵּׁנִית לְצֵאתָם מֵאֶרֶץ מִצְרַיִם לֵאמֹר׃
שְׂאוּ אֶת־רֹאשׁ כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמוֹת כָּל־זָכָר לְגֻלְגְּלֹתָם׃
מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כָּל־יֹצֵא צָבָא בְּיִשְׂרָאֵל תִּפְקְדוּ אֹתָם לְצִבְאֹתָם אַתָּה וְאַהֲרֹן׃
וְאִתְּכֶם יִהְיוּ אִישׁ אִישׁ לַמַּטֶּה אִישׁ רֹאשׁ לְבֵית־אֲבֹתָיו הוּא׃
וְאֵלֶּה שְׁמוֹת הָאֲנָשִׁים אֲשֶׁר יַעַמְדוּ אִתְּכֶם לִרְאוּבֵן אֱלִיצוּר בֶּן־שְׁדֵיאוּר׃
לְשִׁמְעוֹן שְׁלֻמִיאֵל בֶּן־צוּרִישַׁדָּי׃
לִיהוּדָה נַחְשׁוֹן בֶּן־עַמִּינָדָב׃
לְיִשָּׂשכָר נְתַנְאֵל בֶּן־צוּעָר׃
לִזְבוּלֻן אֱלִיאָב בֶּן־חֵלֹן׃
לִבְנֵי יוֹסֵף לְאֶפְרַיִם אֱלִישָׁמָע בֶּן־עַמִּיהוּד לִמְנַשֶּׁה גַּמְלִיאֵל בֶּן־פְּדָהצוּר׃
לְבִנְיָמִן אֲבִידָן בֶּן־גִּדְעֹנִי׃
לְדָן אֲחִיעֶזֶר בֶּן־עַמִּישַׁדָּי׃
לְאָשֵׁר פַּגְעִיאֵל בֶּן־עָכְרָן׃
לְגָד אֶלְיָסָף בֶּן־דְּעוּאֵל׃
לְנַפְתָּלִי אֲחִירַע בֶּן־עֵינָן׃
אֵלֶּה קריאי [קְרוּאֵי] הָעֵדָה נְשִׂיאֵי מַטּוֹת אֲבוֹתָם רָאשֵׁי אַלְפֵי יִשְׂרָאֵל הֵם׃
וַיִּקַּח מֹשֶׁה וְאַהֲרֹן אֵת הָאֲנָשִׁים הָאֵלֶּה אֲשֶׁר נִקְּבוּ בְּשֵׁמוֹת׃
וְאֵת כָּל־הָעֵדָה הִקְהִילוּ בְּאֶחָד לַחֹדֶשׁ הַשֵּׁנִי וַיִּתְיַלְדוּ עַל־מִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמוֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה לְגֻלְגְּלֹתָם׃
כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה וַיִּפְקְדֵם בְּמִדְבַּר סִינָי׃
וַיִּהְיוּ בְנֵי־רְאוּבֵן בְּכֹר יִשְׂרָאֵל תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמוֹת לְגֻלְגְּלֹתָם כָּל־זָכָר מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה רְאוּבֵן שִׁשָּׁה וְאַרְבָּעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
לִבְנֵי שִׁמְעוֹן תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם פְּקֻדָיו בְּמִסְפַּר שֵׁמוֹת לְגֻלְגְּלֹתָם כָּל־זָכָר מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה שִׁמְעוֹן תִּשְׁעָה וַחֲמִשִּׁים אֶלֶף וּשְׁלֹשׁ מֵאוֹת׃
לִבְנֵי גָד תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמוֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה גָד חֲמִשָּׁה וְאַרְבָּעִים אֶלֶף וְשֵׁשׁ מֵאוֹת וַחֲמִשִּׁים׃
לִבְנֵי יְהוּדָה תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה יְהוּדָה אַרְבָּעָה וְשִׁבְעִים אֶלֶף וְשֵׁשׁ מֵאוֹת׃
לִבְנֵי יִשָּׂשכָר תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה יִשָּׂשכָר אַרְבָּעָה וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
לִבְנֵי זְבוּלֻן תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה זְבוּלֻן שִׁבְעָה וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
לִבְנֵי יוֹסֵף לִבְנֵי אֶפְרַיִם תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה אֶפְרָיִם אַרְבָּעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
לִבְנֵי מְנַשֶּׁה תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמוֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה מְנַשֶּׁה שְׁנַיִם וּשְׁלֹשִׁים אֶלֶף וּמָאתָיִם׃
לִבְנֵי בִנְיָמִן תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה בִנְיָמִן חֲמִשָּׁה וּשְׁלֹשִׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
לִבְנֵי דָן תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה דָן שְׁנַיִם וְשִׁשִּׁים אֶלֶף וּשְׁבַע מֵאוֹת׃
לִבְנֵי אָשֵׁר תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה אָשֵׁר אֶחָד וְאַרְבָּעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
בְּנֵי נַפְתָּלִי תּוֹלְדֹתָם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם בְּמִסְפַּר שֵׁמֹת מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כֹּל יֹצֵא צָבָא׃
פְּקֻדֵיהֶם לְמַטֵּה נַפְתָּלִי שְׁלֹשָׁה וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
אֵלֶּה הַפְּקֻדִים אֲשֶׁר פָּקַד מֹשֶׁה וְאַהֲרֹן וּנְשִׂיאֵי יִשְׂרָאֵל שְׁנֵים עָשָׂר אִישׁ אִישׁ־אֶחָד לְבֵית־אֲבֹתָיו הָיוּ׃
וַיִּהְיוּ כָּל־פְּקוּדֵי בְנֵי־יִשְׂרָאֵל לְבֵית אֲבֹתָם מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה כָּל־יֹצֵא צָבָא בְּיִשְׂרָאֵל׃
וַיִּהְיוּ כָּל־הַפְּקֻדִים שֵׁשׁ־מֵאוֹת אֶלֶף וּשְׁלֹשֶׁת אֲלָפִים וַחֲמֵשׁ מֵאוֹת וַחֲמִשִּׁים׃
וְהַלְוִיִּם לְמַטֵּה אֲבֹתָם לֹא הָתְפָּקְדוּ בְּתוֹכָם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
אַךְ אֶת־מַטֵּה לֵוִי לֹא תִפְקֹד וְאֶת־רֹאשָׁם לֹא תִשָּׂא בְּתוֹךְ בְּנֵי יִשְׂרָאֵל׃
וְאַתָּה הַפְקֵד אֶת־הַלְוִיִּם עַל־מִשְׁכַּן הָעֵדֻת וְעַל כָּל־כֵּלָיו וְעַל כָּל־אֲשֶׁר־לוֹ הֵמָּה יִשְׂאוּ אֶת־הַמִּשְׁכָּן וְאֶת־כָּל־כֵּלָיו וְהֵם יְשָׁרְתֻהוּ וְסָבִיב לַמִּשְׁכָּן יַחֲנוּ׃
וּבִנְסֹעַ הַמִּשְׁכָּן יוֹרִידוּ אֹתוֹ הַלְוִיִּם וּבַחֲנֹת הַמִּשְׁכָּן יָקִימוּ אֹתוֹ הַלְוִיִּם וְהַזָּר הַקָּרֵב יוּמָת׃
וְחָנוּ בְּנֵי יִשְׂרָאֵל אִישׁ עַל־מַחֲנֵהוּ וְאִישׁ עַל־דִּגְלוֹ לְצִבְאֹתָם׃
וְהַלְוִיִּם יַחֲנוּ סָבִיב לְמִשְׁכַּן הָעֵדֻת וְלֹא־יִהְיֶה קֶצֶף עַל־עֲדַת בְּנֵי יִשְׂרָאֵל וְשָׁמְרוּ הַלְוִיִּם אֶת־מִשְׁמֶרֶת מִשְׁכַּן הָעֵדוּת׃
וַיַּעֲשׂוּ בְּנֵי יִשְׂרָאֵל כְּכֹל אֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה כֵּן עָשׂוּ׃

Chapter 2

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
אִישׁ עַל־דִּגְלוֹ בְאֹתֹת לְבֵית אֲבֹתָם יַחֲנוּ בְּנֵי יִשְׂרָאֵל מִנֶּגֶד סָבִיב לְאֹהֶל־מוֹעֵד יַחֲנוּ׃
וְהַחֹנִים קֵדְמָה מִזְרָחָה דֶּגֶל מַחֲנֵה יְהוּדָה לְצִבְאֹתָם וְנָשִׂיא לִבְנֵי יְהוּדָה נַחְשׁוֹן בֶּן־עַמִּינָדָב׃
וּצְבָאוֹ וּפְקֻדֵיהֶם אַרְבָּעָה וְשִׁבְעִים אֶלֶף וְשֵׁשׁ מֵאוֹת׃
וְהַחֹנִים עָלָיו מַטֵּה יִשָּׂשכָר וְנָשִׂיא לִבְנֵי יִשָּׂשכָר נְתַנְאֵל בֶּן־צוּעָר׃
וּצְבָאוֹ וּפְקֻדָיו אַרְבָּעָה וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
מַטֵּה זְבוּלֻן וְנָשִׂיא לִבְנֵי זְבוּלֻן אֱלִיאָב בֶּן־חֵלֹן׃
וּצְבָאוֹ וּפְקֻדָיו שִׁבְעָה וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
כָּל־הַפְּקֻדִים לְמַחֲנֵה יְהוּדָה מְאַת אֶלֶף וּשְׁמֹנִים אֶלֶף וְשֵׁשֶׁת־אֲלָפִים וְאַרְבַּע־מֵאוֹת לְצִבְאֹתָם רִאשֹׁנָה יִסָּעוּ׃
דֶּגֶל מַחֲנֵה רְאוּבֵן תֵּימָנָה לְצִבְאֹתָם וְנָשִׂיא לִבְנֵי רְאוּבֵן אֱלִיצוּר בֶּן־שְׁדֵיאוּר׃
וּצְבָאוֹ וּפְקֻדָיו שִׁשָּׁה וְאַרְבָּעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
וְהַחוֹנִם עָלָיו מַטֵּה שִׁמְעוֹן וְנָשִׂיא לִבְנֵי שִׁמְעוֹן שְׁלֻמִיאֵל בֶּן־צוּרִי־שַׁדָּי׃
וּצְבָאוֹ וּפְקֻדֵיהֶם תִּשְׁעָה וַחֲמִשִּׁים אֶלֶף וּשְׁלֹשׁ מֵאוֹת׃
וְמַטֵּה גָּד וְנָשִׂיא לִבְנֵי גָד אֶלְיָסָף בֶּן־רְעוּאֵל׃
וּצְבָאוֹ וּפְקֻדֵיהֶם חֲמִשָּׁה וְאַרְבָּעִים אֶלֶף וְשֵׁשׁ מֵאוֹת וַחֲמִשִּׁים׃
כָּל־הַפְּקֻדִים לְמַחֲנֵה רְאוּבֵן מְאַת אֶלֶף וְאֶחָד וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע־מֵאוֹת וַחֲמִשִּׁים לְצִבְאֹתָם וּשְׁנִיִּם יִסָּעוּ׃
וְנָסַע אֹהֶל־מוֹעֵד מַחֲנֵה הַלְוִיִּם בְּתוֹךְ הַמַּחֲנֹת כַּאֲשֶׁר יַחֲנוּ כֵּן יִסָּעוּ אִישׁ עַל־יָדוֹ לְדִגְלֵיהֶם׃
דֶּגֶל מַחֲנֵה אֶפְרַיִם לְצִבְאֹתָם יָמָּה וְנָשִׂיא לִבְנֵי אֶפְרַיִם אֱלִישָׁמָע בֶּן־עַמִּיהוּד׃
וּצְבָאוֹ וּפְקֻדֵיהֶם אַרְבָּעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
וְעָלָיו מַטֵּה מְנַשֶּׁה וְנָשִׂיא לִבְנֵי מְנַשֶּׁה גַּמְלִיאֵל בֶּן־פְּדָהצוּר׃
וּצְבָאוֹ וּפְקֻדֵיהֶם שְׁנַיִם וּשְׁלֹשִׁים אֶלֶף וּמָאתָיִם׃
וּמַטֵּה בִּנְיָמִן וְנָשִׂיא לִבְנֵי בִנְיָמִן אֲבִידָן בֶּן־גִּדְעֹנִי׃
וּצְבָאוֹ וּפְקֻדֵיהֶם חֲמִשָּׁה וּשְׁלֹשִׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
כָּל־הַפְּקֻדִים לְמַחֲנֵה אֶפְרַיִם מְאַת אֶלֶף וּשְׁמֹנַת־אֲלָפִים וּמֵאָה לְצִבְאֹתָם וּשְׁלִשִׁים יִסָּעוּ׃
דֶּגֶל מַחֲנֵה דָן צָפֹנָה לְצִבְאֹתָם וְנָשִׂיא לִבְנֵי דָן אֲחִיעֶזֶר בֶּן־עַמִּישַׁדָּי׃
וּצְבָאוֹ וּפְקֻדֵיהֶם שְׁנַיִם וְשִׁשִּׁים אֶלֶף וּשְׁבַע מֵאוֹת׃
וְהַחֹנִים עָלָיו מַטֵּה אָשֵׁר וְנָשִׂיא לִבְנֵי אָשֵׁר פַּגְעִיאֵל בֶּן־עָכְרָן׃
וּצְבָאוֹ וּפְקֻדֵיהֶם אֶחָד וְאַרְבָּעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
וּמַטֵּה נַפְתָּלִי וְנָשִׂיא לִבְנֵי נַפְתָּלִי אֲחִירַע בֶּן־עֵינָן׃
וּצְבָאוֹ וּפְקֻדֵיהֶם שְׁלֹשָׁה וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
כָּל־הַפְּקֻדִים לְמַחֲנֵה דָן מְאַת אֶלֶף וְשִׁבְעָה וַחֲמִשִּׁים אֶלֶף וְשֵׁשׁ מֵאוֹת לָאַחֲרֹנָה יִסְעוּ לְדִגְלֵיהֶם׃
אֵלֶּה פְּקוּדֵי בְנֵי־יִשְׂרָאֵל לְבֵית אֲבֹתָם כָּל־פְּקוּדֵי הַמַּחֲנֹת לְצִבְאֹתָם שֵׁשׁ־מֵאוֹת אֶלֶף וּשְׁלֹשֶׁת אֲלָפִים וַחֲמֵשׁ מֵאוֹת וַחֲמִשִּׁים׃
וְהַלְוִיִּם לֹא הָתְפָּקְדוּ בְּתוֹךְ בְּנֵי יִשְׂרָאֵל כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיַּעֲשׂוּ בְּנֵי יִשְׂרָאֵל כְּכֹל אֲשֶׁר־צִוָּה יְהוָה אֶת־מֹשֶׁה כֵּן־חָנוּ לְדִגְלֵיהֶם וְכֵן נָסָעוּ אִישׁ לְמִשְׁפְּחֹתָיו עַל־בֵּית אֲבֹתָיו׃

Chapter 3

וְאֵלֶּה תּוֹלְדֹת אַהֲרֹן וּמֹשֶׁה בְּיוֹם דִּבֶּר יְהוָה אֶת־מֹשֶׁה בְּהַר סִינָי׃
וְאֵלֶּה שְׁמוֹת בְּנֵי־אַהֲרֹן הַבְּכוֹר נָדָב וַאֲבִיהוּא אֶלְעָזָר וְאִיתָמָר׃
אֵלֶּה שְׁמוֹת בְּנֵי אַהֲרֹן הַכֹּהֲנִים הַמְּשֻׁחִים אֲשֶׁר־מִלֵּא יָדָם לְכַהֵן׃
וַיָּמָת נָדָב וַאֲבִיהוּא לִפְנֵי יְהוָה בְּהַקְרִבָם אֵשׁ זָרָה לִפְנֵי יְהוָה בְּמִדְבַּר סִינַי וּבָנִים לֹא־הָיוּ לָהֶם וַיְכַהֵן אֶלְעָזָר וְאִיתָמָר עַל־פְּנֵי אַהֲרֹן אֲבִיהֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
הַקְרֵב אֶת־מַטֵּה לֵוִי וְהַעֲמַדְתָּ אֹתוֹ לִפְנֵי אַהֲרֹן הַכֹּהֵן וְשֵׁרְתוּ אֹתוֹ׃
וְשָׁמְרוּ אֶת־מִשְׁמַרְתּוֹ וְאֶת־מִשְׁמֶרֶת כָּל־הָעֵדָה לִפְנֵי אֹהֶל מוֹעֵד לַעֲבֹד אֶת־עֲבֹדַת הַמִּשְׁכָּן׃
וְשָׁמְרוּ אֶת־כָּל־כְּלֵי אֹהֶל מוֹעֵד וְאֶת־מִשְׁמֶרֶת בְּנֵי יִשְׂרָאֵל לַעֲבֹד אֶת־עֲבֹדַת הַמִּשְׁכָּן׃
וְנָתַתָּה אֶת־הַלְוִיִּם לְאַהֲרֹן וּלְבָנָיו נְתוּנִם נְתוּנִם הֵמָּה לוֹ מֵאֵת בְּנֵי יִשְׂרָאֵל׃
וְאֶת־אַהֲרֹן וְאֶת־בָּנָיו תִּפְקֹד וְשָׁמְרוּ אֶת־כְּהֻנָּתָם וְהַזָּר הַקָּרֵב יוּמָת׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
וַאֲנִי הִנֵּה לָקַחְתִּי אֶת־הַלְוִיִּם מִתּוֹךְ בְּנֵי יִשְׂרָאֵל תַּחַת כָּל־בְּכוֹר פֶּטֶר רֶחֶם מִבְּנֵי יִשְׂרָאֵל וְהָיוּ לִי הַלְוִיִּם׃
כִּי לִי כָּל־בְּכוֹר בְּיוֹם הַכֹּתִי כָל־בְּכוֹר בְּאֶרֶץ מִצְרַיִם הִקְדַּשְׁתִּי לִי כָל־בְּכוֹר בְּיִשְׂרָאֵל מֵאָדָם עַד־בְּהֵמָה לִי יִהְיוּ אֲנִי יְהוָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה בְּמִדְבַּר סִינַי לֵאמֹר׃
פְּקֹד אֶת־בְּנֵי לֵוִי לְבֵית אֲבֹתָם לְמִשְׁפְּחֹתָם כָּל־זָכָר מִבֶּן־חֹדֶשׁ וָמַעְלָה תִּפְקְדֵם׃
וַיִּפְקֹד אֹתָם מֹשֶׁה עַל־פִּי יְהוָה כַּאֲשֶׁר צֻוָּה׃
וַיִּהְיוּ־אֵלֶּה בְנֵי־לֵוִי בִּשְׁמֹתָם גֵּרְשׁוֹן וּקְהָת וּמְרָרִי׃
וְאֵלֶּה שְׁמוֹת בְּנֵי־גֵרְשׁוֹן לְמִשְׁפְּחֹתָם לִבְנִי וְשִׁמְעִי׃
וּבְנֵי קְהָת לְמִשְׁפְּחֹתָם עַמְרָם וְיִצְהָר חֶבְרוֹן וְעֻזִּיאֵל׃
וּבְנֵי מְרָרִי לְמִשְׁפְּחֹתָם מַחְלִי וּמוּשִׁי אֵלֶּה הֵם מִשְׁפְּחֹת הַלֵּוִי לְבֵית אֲבֹתָם׃
לְגֵרְשׁוֹן מִשְׁפַּחַת הַלִּבְנִי וּמִשְׁפַּחַת הַשִּׁמְעִי אֵלֶּה הֵם מִשְׁפְּחֹת הַגֵּרְשֻׁנִּי׃
פְּקֻדֵיהֶם בְּמִסְפַּר כָּל־זָכָר מִבֶּן־חֹדֶשׁ וָמָעְלָה פְּקֻדֵיהֶם שִׁבְעַת אֲלָפִים וַחֲמֵשׁ מֵאוֹת׃
מִשְׁפְּחֹת הַגֵּרְשֻׁנִּי אַחֲרֵי הַמִּשְׁכָּן יַחֲנוּ יָמָּה׃
וּנְשִׂיא בֵית־אָב לַגֵּרְשֻׁנִּי אֶלְיָסָף בֶּן־לָאֵל׃
וּמִשְׁמֶרֶת בְּנֵי־גֵרְשׁוֹן בְּאֹהֶל מוֹעֵד הַמִּשְׁכָּן וְהָאֹהֶל מִכְסֵהוּ וּמָסַךְ פֶּתַח אֹהֶל מוֹעֵד׃
וְקַלְעֵי הֶחָצֵר וְאֶת־מָסַךְ פֶּתַח הֶחָצֵר אֲשֶׁר עַל־הַמִּשְׁכָּן וְעַל־הַמִּזְבֵּחַ סָבִיב וְאֵת מֵיתָרָיו לְכֹל עֲבֹדָתוֹ׃
וְלִקְהָת מִשְׁפַּחַת הַעַמְרָמִי וּמִשְׁפַּחַת הַיִּצְהָרִי וּמִשְׁפַּחַת הַחֶבְרֹנִי וּמִשְׁפַּחַת הָעָזִּיאֵלִי אֵלֶּה הֵם מִשְׁפְּחֹת הַקְּהָתִי׃
בְּמִסְפַּר כָּל־זָכָר מִבֶּן־חֹדֶשׁ וָמָעְלָה שְׁמֹנַת אֲלָפִים וְשֵׁשׁ מֵאוֹת שֹׁמְרֵי מִשְׁמֶרֶת הַקֹּדֶשׁ׃
מִשְׁפְּחֹת בְּנֵי־קְהָת יַחֲנוּ עַל יֶרֶךְ הַמִּשְׁכָּן תֵּימָנָה׃
וּנְשִׂיא בֵית־אָב לְמִשְׁפְּחֹת הַקְּהָתִי אֶלִיצָפָן בֶּן־עֻזִּיאֵל׃
וּמִשְׁמַרְתָּם הָאָרֹן וְהַשֻּׁלְחָן וְהַמְּנֹרָה וְהַמִּזְבְּחֹת וּכְלֵי הַקֹּדֶשׁ אֲשֶׁר יְשָׁרְתוּ בָּהֶם וְהַמָּסָךְ וְכֹל עֲבֹדָתוֹ׃
וּנְשִׂיא נְשִׂיאֵי הַלֵּוִי אֶלְעָזָר בֶּן־אַהֲרֹן הַכֹּהֵן פְּקֻדַּת שֹׁמְרֵי מִשְׁמֶרֶת הַקֹּדֶשׁ׃
לִמְרָרִי מִשְׁפַּחַת הַמַּחְלִי וּמִשְׁפַּחַת הַמּוּשִׁי אֵלֶּה הֵם מִשְׁפְּחֹת מְרָרִי׃
וּפְקֻדֵיהֶם בְּמִסְפַּר כָּל־זָכָר מִבֶּן־חֹדֶשׁ וָמָעְלָה שֵׁשֶׁת אֲלָפִים וּמָאתָיִם׃
וּנְשִׂיא בֵית־אָב לְמִשְׁפְּחֹת מְרָרִי צוּרִיאֵל בֶּן־אֲבִיחָיִל עַל יֶרֶךְ הַמִּשְׁכָּן יַחֲנוּ צָפֹנָה׃
וּפְקֻדַּת מִשְׁמֶרֶת בְּנֵי מְרָרִי קַרְשֵׁי הַמִּשְׁכָּן וּבְרִיחָיו וְעַמֻּדָיו וַאֲדָנָיו וְכָל־כֵּלָיו וְכֹל עֲבֹדָתוֹ׃
וְעַמֻּדֵי הֶחָצֵר סָבִיב וְאַדְנֵיהֶם וִיתֵדֹתָם וּמֵיתְרֵיהֶם׃
וְהַחֹנִים לִפְנֵי הַמִּשְׁכָּן קֵדְמָה לִפְנֵי אֹהֶל־מוֹעֵד מִזְרָחָה מֹשֶׁה וְאַהֲרֹן וּבָנָיו שֹׁמְרִים מִשְׁמֶרֶת הַמִּקְדָּשׁ לְמִשְׁמֶרֶת בְּנֵי יִשְׂרָאֵל וְהַזָּר הַקָּרֵב יוּמָת׃
כָּל־פְּקוּדֵי הַלְוִיִּם אֲשֶׁר פָּקַד מֹשֶׁה וְאַהֲרֹן עַל־פִּי יְהוָה לְמִשְׁפְּחֹתָם כָּל־זָכָר מִבֶּן־חֹדֶשׁ וָמַעְלָה שְׁנַיִם וְעֶשְׂרִים אָלֶף׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה פְּקֹד כָּל־בְּכֹר זָכָר לִבְנֵי יִשְׂרָאֵל מִבֶּן־חֹדֶשׁ וָמָעְלָה וְשָׂא אֵת מִסְפַּר שְׁמֹתָם׃
וְלָקַחְתָּ אֶת־הַלְוִיִּם לִי אֲנִי יְהוָה תַּחַת כָּל־בְּכֹר בִּבְנֵי יִשְׂרָאֵל וְאֵת בֶּהֱמַת הַלְוִיִּם תַּחַת כָּל־בְּכוֹר בְּבֶהֱמַת בְּנֵי יִשְׂרָאֵל׃
וַיִּפְקֹד מֹשֶׁה כַּאֲשֶׁר צִוָּה יְהוָה אֹתוֹ אֶת־כָּל־בְּכֹר בִּבְנֵי יִשְׂרָאֵל׃
וַיְהִי כָל־בְּכוֹר זָכָר בְּמִסְפַּר שֵׁמוֹת מִבֶּן־חֹדֶשׁ וָמַעְלָה לִפְקֻדֵיהֶם שְׁנַיִם וְעֶשְׂרִים אֶלֶף שְׁלֹשָׁה וְשִׁבְעִים וּמָאתָיִם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
קַח אֶת־הַלְוִיִּם תַּחַת כָּל־בְּכוֹר בִּבְנֵי יִשְׂרָאֵל וְאֶת־בֶּהֱמַת הַלְוִיִּם תַּחַת בְּהֶמְתָּם וְהָיוּ־לִי הַלְוִיִּם אֲנִי יְהוָה׃
וְאֵת פְּדוּיֵי הַשְּׁלֹשָׁה וְהַשִּׁבְעִים וְהַמָּאתָיִם הָעֹדְפִים עַל־הַלְוִיִּם מִבְּכוֹר בְּנֵי יִשְׂרָאֵל׃
וְלָקַחְתָּ חֲמֵשֶׁת חֲמֵשֶׁת שְׁקָלִים לַגֻּלְגֹּלֶת בְּשֶׁקֶל הַקֹּדֶשׁ תִּקָּח עֶשְׂרִים גֵּרָה הַשָּׁקֶל׃
וְנָתַתָּה הַכֶּסֶף לְאַהֲרֹן וּלְבָנָיו פְּדוּיֵי הָעֹדְפִים בָּהֶם׃
וַיִּקַּח מֹשֶׁה אֵת כֶּסֶף הַפִּדְיוֹם מֵאֵת הָעֹדְפִים עַל פְּדוּיֵי הַלְוִיִּם׃
מֵאֵת בְּכוֹר בְּנֵי יִשְׂרָאֵל לָקַח אֶת־הַכָּסֶף חֲמִשָּׁה וְשִׁשִּׁים וּשְׁלֹשׁ מֵאוֹת וָאֶלֶף בְּשֶׁקֶל הַקֹּדֶשׁ׃
וַיִּתֵּן מֹשֶׁה אֶת־כֶּסֶף הַפְּדֻיִם לְאַהֲרֹן וּלְבָנָיו עַל־פִּי יְהוָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃

Chapter 4

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
נָשֹׂא אֶת־רֹאשׁ בְּנֵי קְהָת מִתּוֹךְ בְּנֵי לֵוִי לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם׃
מִבֶּן שְׁלֹשִׁים שָׁנָה וָמַעְלָה וְעַד בֶּן־חֲמִשִּׁים שָׁנָה כָּל־בָּא לַצָּבָא לַעֲשׂוֹת מְלָאכָה בְּאֹהֶל מוֹעֵד׃
זֹאת עֲבֹדַת בְּנֵי־קְהָת בְּאֹהֶל מוֹעֵד קֹדֶשׁ הַקֳּדָשִׁים׃
וּבָא אַהֲרֹן וּבָנָיו בִּנְסֹעַ הַמַּחֲנֶה וְהוֹרִדוּ אֵת פָּרֹכֶת הַמָּסָךְ וְכִסּוּ־בָהּ אֵת אֲרֹן הָעֵדֻת׃
וְנָתְנוּ עָלָיו כְּסוּי עוֹר תַּחַשׁ וּפָרְשׂוּ בֶגֶד־כְּלִיל תְּכֵלֶת מִלְמָעְלָה וְשָׂמוּ בַּדָּיו׃
וְעַל שֻׁלְחַן הַפָּנִים יִפְרְשׂוּ בֶּגֶד תְּכֵלֶת וְנָתְנוּ עָלָיו אֶת־הַקְּעָרֹת וְאֶת־הַכַּפֹּת וְאֶת־הַמְּנַקִּיֹּת וְאֵת קְשׂוֹת הַנָּסֶךְ וְלֶחֶם הַתָּמִיד עָלָיו יִהְיֶה׃
וּפָרְשׂוּ עֲלֵיהֶם בֶּגֶד תּוֹלַעַת שָׁנִי וְכִסּוּ אֹתוֹ בְּמִכְסֵה עוֹר תָּחַשׁ וְשָׂמוּ אֶת־בַּדָּיו׃
וְלָקְחוּ בֶּגֶד תְּכֵלֶת וְכִסּוּ אֶת־מְנֹרַת הַמָּאוֹר וְאֶת־נֵרֹתֶיהָ וְאֶת־מַלְקָחֶיהָ וְאֶת־מַחְתֹּתֶיהָ וְאֵת כָּל־כְּלֵי שַׁמְנָהּ אֲשֶׁר יְשָׁרְתוּ־לָהּ בָּהֶם׃
וְנָתְנוּ אֹתָהּ וְאֶת־כָּל־כֵּלֶיהָ אֶל־מִכְסֵה עוֹר תָּחַשׁ וְנָתְנוּ עַל־הַמּוֹט׃
וְעַל מִזְבַּח הַזָּהָב יִפְרְשׂוּ בֶּגֶד תְּכֵלֶת וְכִסּוּ אֹתוֹ בְּמִכְסֵה עוֹר תָּחַשׁ וְשָׂמוּ אֶת־בַּדָּיו׃
וְלָקְחוּ אֶת־כָּל־כְּלֵי הַשָּׁרֵת אֲשֶׁר יְשָׁרְתוּ־בָם בַּקֹּדֶשׁ וְנָתְנוּ אֶל־בֶּגֶד תְּכֵלֶת וְכִסּוּ אוֹתָם בְּמִכְסֵה עוֹר תָּחַשׁ וְנָתְנוּ עַל־הַמּוֹט׃
וְדִשְּׁנוּ אֶת־הַמִּזְבֵּחַ וּפָרְשׂוּ עָלָיו בֶּגֶד אַרְגָּמָן׃
וְנָתְנוּ עָלָיו אֶת־כָּל־כֵּלָיו אֲשֶׁר יְשָׁרְתוּ עָלָיו בָּהֶם אֶת־הַמַּחְתֹּת אֶת־הַמִּזְלָגֹת וְאֶת־הַיָּעִים וְאֶת־הַמִּזְרָקֹת כֹּל כְּלֵי הַמִּזְבֵּחַ וּפָרְשׂוּ עָלָיו כְּסוּי עוֹר תַּחַשׁ וְשָׂמוּ בַדָּיו׃
וְכִלָּה אַהֲרֹן־וּבָנָיו לְכַסֹּת אֶת־הַקֹּדֶשׁ וְאֶת־כָּל־כְּלֵי הַקֹּדֶשׁ בִּנְסֹעַ הַמַּחֲנֶה וְאַחֲרֵי־כֵן יָבֹאוּ בְנֵי־קְהָת לָשֵׂאת וְלֹא־יִגְּעוּ אֶל־הַקֹּדֶשׁ וָמֵתוּ אֵלֶּה מַשָּׂא בְנֵי־קְהָת בְּאֹהֶל מוֹעֵד׃
וּפְקֻדַּת אֶלְעָזָר בֶּן־אַהֲרֹן הַכֹּהֵן שֶׁמֶן הַמָּאוֹר וּקְטֹרֶת הַסַּמִּים וּמִנְחַת הַתָּמִיד וְשֶׁמֶן הַמִּשְׁחָה פְּקֻדַּת כָּל־הַמִּשְׁכָּן וְכָל־אֲשֶׁר־בּוֹ בְּקֹדֶשׁ וּבְכֵלָיו׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
אַל־תַּכְרִיתוּ אֶת־שֵׁבֶט מִשְׁפְּחֹת הַקְּהָתִי מִתּוֹךְ הַלְוִיִּם׃
וְזֹאת עֲשׂוּ לָהֶם וְחָיוּ וְלֹא יָמֻתוּ בְּגִשְׁתָּם אֶת־קֹדֶשׁ הַקֳּדָשִׁים אַהֲרֹן וּבָנָיו יָבֹאוּ וְשָׂמוּ אוֹתָם אִישׁ אִישׁ עַל־עֲבֹדָתוֹ וְאֶל־מַשָּׂאוֹ׃
וְלֹא־יָבֹאוּ לִרְאוֹת כְּבַלַּע אֶת־הַקֹּדֶשׁ וָמֵתוּ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
נָשֹׂא אֶת־רֹאשׁ בְּנֵי גֵרְשׁוֹן גַּם־הֵם לְבֵית אֲבֹתָם לְמִשְׁפְּחֹתָם׃
מִבֶּן שְׁלֹשִׁים שָׁנָה וָמַעְלָה עַד בֶּן־חֲמִשִּׁים שָׁנָה תִּפְקֹד אוֹתָם כָּל־הַבָּא לִצְבֹא צָבָא לַעֲבֹד עֲבֹדָה בְּאֹהֶל מוֹעֵד׃
זֹאת עֲבֹדַת מִשְׁפְּחֹת הַגֵּרְשֻׁנִּי לַעֲבֹד וּלְמַשָּׂא׃
וְנָשְׂאוּ אֶת־יְרִיעֹת הַמִּשְׁכָּן וְאֶת־אֹהֶל מוֹעֵד מִכְסֵהוּ וּמִכְסֵה הַתַּחַשׁ אֲשֶׁר־עָלָיו מִלְמָעְלָה וְאֶת־מָסַךְ פֶּתַח אֹהֶל מוֹעֵד׃
וְאֵת קַלְעֵי הֶחָצֵר וְאֶת־מָסַךְ פֶּתַח שַׁעַר הֶחָצֵר אֲשֶׁר עַל־הַמִּשְׁכָּן וְעַל־הַמִּזְבֵּחַ סָבִיב וְאֵת מֵיתְרֵיהֶם וְאֶת־כָּל־כְּלֵי עֲבֹדָתָם וְאֵת כָּל־אֲשֶׁר יֵעָשֶׂה לָהֶם וְעָבָדוּ׃
עַל־פִּי אַהֲרֹן וּבָנָיו תִּהְיֶה כָּל־עֲבֹדַת בְּנֵי הַגֵּרְשֻׁנִּי לְכָל־מַשָּׂאָם וּלְכֹל עֲבֹדָתָם וּפְקַדְתֶּם עֲלֵהֶם בְּמִשְׁמֶרֶת אֵת כָּל־מַשָּׂאָם׃
זֹאת עֲבֹדַת מִשְׁפְּחֹת בְּנֵי הַגֵּרְשֻׁנִּי בְּאֹהֶל מוֹעֵד וּמִשְׁמַרְתָּם בְּיַד אִיתָמָר בֶּן־אַהֲרֹן הַכֹּהֵן׃
בְּנֵי מְרָרִי לְמִשְׁפְּחֹתָם לְבֵית־אֲבֹתָם תִּפְקֹד אֹתָם׃
מִבֶּן שְׁלֹשִׁים שָׁנָה וָמַעְלָה וְעַד בֶּן־חֲמִשִּׁים שָׁנָה תִּפְקְדֵם כָּל־הַבָּא לַצָּבָא לַעֲבֹד אֶת־עֲבֹדַת אֹהֶל מוֹעֵד׃
וְזֹאת מִשְׁמֶרֶת מַשָּׂאָם לְכָל־עֲבֹדָתָם בְּאֹהֶל מוֹעֵד קַרְשֵׁי הַמִּשְׁכָּן וּבְרִיחָיו וְעַמּוּדָיו וַאֲדָנָיו׃
וְעַמּוּדֵי הֶחָצֵר סָבִיב וְאַדְנֵיהֶם וִיתֵדֹתָם וּמֵיתְרֵיהֶם לְכָל־כְּלֵיהֶם וּלְכֹל עֲבֹדָתָם וּבְשֵׁמֹת תִּפְקְדוּ אֶת־כְּלֵי מִשְׁמֶרֶת מַשָּׂאָם׃
זֹאת עֲבֹדַת מִשְׁפְּחֹת בְּנֵי מְרָרִי לְכָל־עֲבֹדָתָם בְּאֹהֶל מוֹעֵד בְּיַד אִיתָמָר בֶּן־אַהֲרֹן הַכֹּהֵן׃
וַיִּפְקֹד מֹשֶׁה וְאַהֲרֹן וּנְשִׂיאֵי הָעֵדָה אֶת־בְּנֵי הַקְּהָתִי לְמִשְׁפְּחֹתָם וּלְבֵית אֲבֹתָם׃
מִבֶּן שְׁלֹשִׁים שָׁנָה וָמַעְלָה וְעַד בֶּן־חֲמִשִּׁים שָׁנָה כָּל־הַבָּא לַצָּבָא לַעֲבֹדָה בְּאֹהֶל מוֹעֵד׃
וַיִּהְיוּ פְקֻדֵיהֶם לְמִשְׁפְּחֹתָם אַלְפַּיִם שְׁבַע מֵאוֹת וַחֲמִשִּׁים׃
אֵלֶּה פְקוּדֵי מִשְׁפְּחֹת הַקְּהָתִי כָּל־הָעֹבֵד בְּאֹהֶל מוֹעֵד אֲשֶׁר פָּקַד מֹשֶׁה וְאַהֲרֹן עַל־פִּי יְהוָה בְּיַד־מֹשֶׁה׃
וּפְקוּדֵי בְּנֵי גֵרְשׁוֹן לְמִשְׁפְּחוֹתָם וּלְבֵית אֲבֹתָם׃
מִבֶּן שְׁלֹשִׁים שָׁנָה וָמַעְלָה וְעַד בֶּן־חֲמִשִּׁים שָׁנָה כָּל־הַבָּא לַצָּבָא לַעֲבֹדָה בְּאֹהֶל מוֹעֵד׃
וַיִּהְיוּ פְּקֻדֵיהֶם לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם אַלְפַּיִם וְשֵׁשׁ מֵאוֹת וּשְׁלֹשִׁים׃
אֵלֶּה פְקוּדֵי מִשְׁפְּחֹת בְּנֵי גֵרְשׁוֹן כָּל־הָעֹבֵד בְּאֹהֶל מוֹעֵד אֲשֶׁר פָּקַד מֹשֶׁה וְאַהֲרֹן עַל־פִּי יְהוָה׃
וּפְקוּדֵי מִשְׁפְּחֹת בְּנֵי מְרָרִי לְמִשְׁפְּחֹתָם לְבֵית אֲבֹתָם׃
מִבֶּן שְׁלֹשִׁים שָׁנָה וָמַעְלָה וְעַד בֶּן־חֲמִשִּׁים שָׁנָה כָּל־הַבָּא לַצָּבָא לַעֲבֹדָה בְּאֹהֶל מוֹעֵד׃
וַיִּהְיוּ פְקֻדֵיהֶם לְמִשְׁפְּחֹתָם שְׁלֹשֶׁת אֲלָפִים וּמָאתָיִם׃
אֵלֶּה פְקוּדֵי מִשְׁפְּחֹת בְּנֵי מְרָרִי אֲשֶׁר פָּקַד מֹשֶׁה וְאַהֲרֹן עַל־פִּי יְהוָה בְּיַד־מֹשֶׁה׃
כָּל־הַפְּקֻדִים אֲשֶׁר פָּקַד מֹשֶׁה וְאַהֲרֹן וּנְשִׂיאֵי יִשְׂרָאֵל אֶת־הַלְוִיִּם לְמִשְׁפְּחֹתָם וּלְבֵית אֲבֹתָם׃
מִבֶּן שְׁלֹשִׁים שָׁנָה וָמַעְלָה וְעַד בֶּן־חֲמִשִּׁים שָׁנָה כָּל־הַבָּא לַעֲבֹד עֲבֹדַת עֲבֹדָה וַעֲבֹדַת מַשָּׂא בְּאֹהֶל מוֹעֵד׃
וַיִּהְיוּ פְּקֻדֵיהֶם שְׁמֹנַת אֲלָפִים וַחֲמֵשׁ מֵאוֹת וּשְׁמֹנִים׃
עַל־פִּי יְהוָה פָּקַד אוֹתָם בְּיַד־מֹשֶׁה אִישׁ אִישׁ עַל־עֲבֹדָתוֹ וְעַל־מַשָּׂאוֹ וּפְקֻדָיו אֲשֶׁר־צִוָּה יְהוָה אֶת־מֹשֶׁה׃

Chapter 5

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
צַו אֶת־בְּנֵי יִשְׂרָאֵל וִישַׁלְּחוּ מִן־הַמַּחֲנֶה כָּל־צָרוּעַ וְכָל־זָב וְכֹל טָמֵא לָנָפֶשׁ׃
מִזָּכָר עַד־נְקֵבָה תְּשַׁלֵּחוּ אֶל־מִחוּץ לַמַּחֲנֶה תְּשַׁלְּחוּם וְלֹא יְטַמְּאוּ אֶת־מַחֲנֵיהֶם אֲשֶׁר אֲנִי שֹׁכֵן בְּתוֹכָם׃
וַיַּעֲשׂוּ־כֵן בְּנֵי יִשְׂרָאֵל וַיְשַׁלְּחוּ אוֹתָם אֶל־מִחוּץ לַמַּחֲנֶה כַּאֲשֶׁר דִּבֶּר יְהוָה אֶל־מֹשֶׁה כֵּן עָשׂוּ בְּנֵי יִשְׂרָאֵל׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל אִישׁ אוֹ־אִשָּׁה כִּי יַעֲשׂוּ מִכָּל־חַטֹּאת הָאָדָם לִמְעֹל מַעַל בַּיהוָה וְאָשְׁמָה הַנֶּפֶשׁ הַהִוא׃
וְהִתְוַדּוּ אֶת־חַטָּאתָם אֲשֶׁר עָשׂוּ וְהֵשִׁיב אֶת־אֲשָׁמוֹ בְּרֹאשׁוֹ וַחֲמִישִׁתוֹ יֹסֵף עָלָיו וְנָתַן לַאֲשֶׁר אָשַׁם לוֹ׃
וְאִם־אֵין לָאִישׁ גֹּאֵל לְהָשִׁיב הָאָשָׁם אֵלָיו הָאָשָׁם הַמּוּשָׁב לַיהוָה לַכֹּהֵן מִלְּבַד אֵיל הַכִּפֻּרִים אֲשֶׁר יְכַפֶּר־בּוֹ עָלָיו׃
וְכָל־תְּרוּמָה לְכָל־קָדְשֵׁי בְנֵי־יִשְׂרָאֵל אֲשֶׁר־יַקְרִיבוּ לַכֹּהֵן לוֹ יִהְיֶה׃
וְאִישׁ אֶת־קֳדָשָׁיו לוֹ יִהְיוּ אִישׁ אֲשֶׁר־יִתֵּן לַכֹּהֵן לוֹ יִהְיֶה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם אִישׁ אִישׁ כִּי־תִשְׂטֶה אִשְׁתּוֹ וּמָעֲלָה בוֹ מָעַל׃
וְשָׁכַב אִישׁ אֹתָהּ שִׁכְבַת־זֶרַע וְנֶעְלַם מֵעֵינֵי אִישָׁהּ וְנִסְתְּרָה וְהִיא נִטְמָאָה וְעֵד אֵין בָּהּ וְהִוא לֹא נִתְפָּשָׂה׃
וְעָבַר עָלָיו רוּחַ־קִנְאָה וְקִנֵּא אֶת־אִשְׁתּוֹ וְהִוא נִטְמָאָה אוֹ־עָבַר עָלָיו רוּחַ־קִנְאָה וְקִנֵּא אֶת־אִשְׁתּוֹ וְהִיא לֹא נִטְמָאָה׃
וְהֵבִיא הָאִישׁ אֶת־אִשְׁתּוֹ אֶל־הַכֹּהֵן וְהֵבִיא אֶת־קָרְבָּנָהּ עָלֶיהָ עֲשִׂירִת הָאֵיפָה קֶמַח שְׂעֹרִים לֹא־יִצֹק עָלָיו שֶׁמֶן וְלֹא־יִתֵּן עָלָיו לְבֹנָה כִּי־מִנְחַת קְנָאֹת הוּא מִנְחַת זִכָּרוֹן מַזְכֶּרֶת עָוֺן׃
וְהִקְרִיב אֹתָהּ הַכֹּהֵן וְהֶעֱמִדָהּ לִפְנֵי יְהוָה׃
וְלָקַח הַכֹּהֵן מַיִם קְדֹשִׁים בִּכְלִי־חָרֶשׂ וּמִן־הֶעָפָר אֲשֶׁר יִהְיֶה בְּקַרְקַע הַמִּשְׁכָּן יִקַּח הַכֹּהֵן וְנָתַן אֶל־הַמָּיִם׃
וְהֶעֱמִיד הַכֹּהֵן אֶת־הָאִשָּׁה לִפְנֵי יְהוָה וּפָרַע אֶת־רֹאשׁ הָאִשָּׁה וְנָתַן עַל־כַּפֶּיהָ אֵת מִנְחַת הַזִּכָּרוֹן מִנְחַת קְנָאֹת הִוא וּבְיַד הַכֹּהֵן יִהְיוּ מֵי הַמָּרִים הַמְאָרֲרִים׃
וְהִשְׁבִּיעַ אֹתָהּ הַכֹּהֵן וְאָמַר אֶל־הָאִשָּׁה אִם־לֹא שָׁכַב אִישׁ אֹתָךְ וְאִם־לֹא שָׂטִית טֻמְאָה תַּחַת אִישֵׁךְ הִנָּקִי מִמֵּי הַמָּרִים הַמְאָרֲרִים הָאֵלֶּה׃
וְאַתְּ כִּי שָׂטִית תַּחַת אִישֵׁךְ וְכִי נִטְמֵאת וַיִּתֵּן אִישׁ בָּךְ אֶת־שְׁכָבְתּוֹ מִבַּלְעֲדֵי אִישֵׁךְ׃
וְהִשְׁבִּיעַ הַכֹּהֵן אֶת־הָאִשָּׁה בִּשְׁבֻעַת הָאָלָה וְאָמַר הַכֹּהֵן לָאִשָּׁה יִתֵּן יְהוָה אוֹתָךְ לְאָלָה וְלִשְׁבֻעָה בְּתוֹךְ עַמֵּךְ בְּתֵת יְהוָה אֶת־יְרֵכֵךְ נֹפֶלֶת וְאֶת־בִּטְנֵךְ צָבָה׃
וּבָאוּ הַמַּיִם הַמְאָרְרִים הָאֵלֶּה בְּמֵעַיִךְ לַצְבּוֹת בֶּטֶן וְלַנְפִּל יָרֵךְ וְאָמְרָה הָאִשָּׁה אָמֵן אָמֵן׃
וְכָתַב אֶת־הָאָלֹת הָאֵלֶּה הַכֹּהֵן בַּסֵּפֶר וּמָחָה אֶל־מֵי הַמָּרִים׃
וְהִשְׁקָה אֶת־הָאִשָּׁה אֶת־מֵי הַמָּרִים הַמְאָרֲרִים וּבָאוּ בָהּ הַמַּיִם הַמְאָרֲרִים לְמָרִים׃
וְלָקַח הַכֹּהֵן מִיַּד הָאִשָּׁה אֵת מִנְחַת הַקְּנָאֹת וְהֵנִיף אֶת־הַמִּנְחָה לִפְנֵי יְהוָה וְהִקְרִיב אֹתָהּ אֶל־הַמִּזְבֵּחַ׃
וְקָמַץ הַכֹּהֵן מִן־הַמִּנְחָה אֶת־אַזְכָּרָתָהּ וְהִקְטִיר הַמִּזְבֵּחָה וְאַחַר יַשְׁקֶה אֶת־הָאִשָּׁה אֶת־הַמָּיִם׃
וְהִשְׁקָהּ אֶת־הַמַּיִם וְהָיְתָה אִם־נִטְמְאָה וַתִּמְעֹל מַעַל בְּאִישָׁהּ וּבָאוּ בָהּ הַמַּיִם הַמְאָרֲרִים לְמָרִים וְצָבְתָה בִטְנָהּ וְנָפְלָה יְרֵכָהּ וְהָיְתָה הָאִשָּׁה לְאָלָה בְּקֶרֶב עַמָּהּ׃
וְאִם־לֹא נִטְמְאָה הָאִשָּׁה וּטְהֹרָה הִוא וְנִקְּתָה וְנִזְרְעָה זָרַע׃
זֹאת תּוֹרַת הַקְּנָאֹת אֲשֶׁר תִּשְׂטֶה אִשָּׁה תַּחַת אִישָׁהּ וְנִטְמָאָה׃
אוֹ אִישׁ אֲשֶׁר תַּעֲבֹר עָלָיו רוּחַ קִנְאָה וְקִנֵּא אֶת־אִשְׁתּוֹ וְהֶעֱמִיד אֶת־הָאִשָּׁה לִפְנֵי יְהוָה וְעָשָׂה לָהּ הַכֹּהֵן אֵת כָּל־הַתּוֹרָה הַזֹּאת׃
וְנִקָּה הָאִישׁ מֵעָוֺן וְהָאִשָּׁה הַהִוא תִּשָּׂא אֶת־עֲוֺנָהּ׃

Chapter 6

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם אִישׁ אוֹ־אִשָּׁה כִּי יַפְלִא לִנְדֹּר נֶדֶר נָזִיר לְהַזִּיר לַיהוָה׃
מִיַּיִן וְשֵׁכָר יַזִּיר חֹמֶץ יַיִן וְחֹמֶץ שֵׁכָר לֹא יִשְׁתֶּה וְכָל־מִשְׁרַת עֲנָבִים לֹא יִשְׁתֶּה וַעֲנָבִים לַחִים וִיבֵשִׁים לֹא יֹאכֵל׃
כֹּל יְמֵי נִזְרוֹ מִכֹּל אֲשֶׁר יֵעָשֶׂה מִגֶּפֶן הַיַּיִן מֵחַרְצַנִּים וְעַד־זָג לֹא יֹאכֵל׃
כָּל־יְמֵי נֶדֶר נִזְרוֹ תַּעַר לֹא־יַעֲבֹר עַל־רֹאשׁוֹ עַד־מְלֹאת הַיָּמִם אֲשֶׁר־יַזִּיר לַיהוָה קָדֹשׁ יִהְיֶה גַּדֵּל פֶּרַע שְׂעַר רֹאשׁוֹ׃
כָּל־יְמֵי הַזִּירוֹ לַיהוָה עַל־נֶפֶשׁ מֵת לֹא יָבֹא׃
לְאָבִיו וּלְאִמּוֹ לְאָחִיו וּלְאַחֹתוֹ לֹא־יִטַּמָּא לָהֶם בְּמֹתָם כִּי נֵזֶר אֱלֹהָיו עַל־רֹאשׁוֹ׃
כֹּל יְמֵי נִזְרוֹ קָדֹשׁ הוּא לַיהוָה׃
וְכִי־יָמוּת מֵת עָלָיו בְּפֶתַע פִּתְאֹם וְטִמֵּא רֹאשׁ נִזְרוֹ וְגִלַּח רֹאשׁוֹ בְּיוֹם טָהֳרָתוֹ בַּיּוֹם הַשְּׁבִיעִי יְגַלְּחֶנּוּ׃
וּבַיּוֹם הַשְּׁמִינִי יָבִא שְׁתֵּי תֹרִים אוֹ שְׁנֵי בְּנֵי יוֹנָה אֶל־הַכֹּהֵן אֶל־פֶּתַח אֹהֶל מוֹעֵד׃
וְעָשָׂה הַכֹּהֵן אֶחָד לְחַטָּאת וְאֶחָד לְעֹלָה וְכִפֶּר עָלָיו מֵאֲשֶׁר חָטָא עַל־הַנָּפֶשׁ וְקִדַּשׁ אֶת־רֹאשׁוֹ בַּיּוֹם הַהוּא׃
וְהִזִּיר לַיהוָה אֶת־יְמֵי נִזְרוֹ וְהֵבִיא כֶּבֶשׂ בֶּן־שְׁנָתוֹ לְאָשָׁם וְהַיָּמִים הָרִאשֹׁנִים יִפְּלוּ כִּי טָמֵא נִזְרוֹ׃
וְזֹאת תּוֹרַת הַנָּזִיר בְּיוֹם מְלֹאת יְמֵי נִזְרוֹ יָבִיא אֹתוֹ אֶל־פֶּתַח אֹהֶל מוֹעֵד׃
וְהִקְרִיב אֶת־קָרְבָּנוֹ לַיהוָה כֶּבֶשׂ בֶּן־שְׁנָתוֹ תָמִים אֶחָד לְעֹלָה וְכַבְשָׂה אַחַת בַּת־שְׁנָתָהּ תְּמִימָה לְחַטָּאת וְאַיִל־אֶחָד תָּמִים לִשְׁלָמִים׃
וְסַל מַצּוֹת סֹלֶת חַלֹּת בְּלוּלֹת בַּשֶּׁמֶן וּרְקִיקֵי מַצּוֹת מְשֻׁחִים בַּשָּׁמֶן וּמִנְחָתָם וְנִסְכֵּיהֶם׃
וְהִקְרִיב הַכֹּהֵן לִפְנֵי יְהוָה וְעָשָׂה אֶת־חַטָּאתוֹ וְאֶת־עֹלָתוֹ׃
וְאֶת־הָאַיִל יַעֲשֶׂה זֶבַח שְׁלָמִים לַיהוָה עַל סַל הַמַּצּוֹת וְעָשָׂה הַכֹּהֵן אֶת־מִנְחָתוֹ וְאֶת־נִסְכּוֹ׃
וְגִלַּח הַנָּזִיר פֶּתַח אֹהֶל מוֹעֵד אֶת־רֹאשׁ נִזְרוֹ וְלָקַח אֶת־שְׂעַר רֹאשׁ נִזְרוֹ וְנָתַן עַל־הָאֵשׁ אֲשֶׁר־תַּחַת זֶבַח הַשְּׁלָמִים׃
וְלָקַח הַכֹּהֵן אֶת־הַזְּרֹעַ בְּשֵׁלָה מִן־הָאַיִל וְחַלַּת מַצָּה אַחַת מִן־הַסַּל וּרְקִיק מַצָּה אֶחָד וְנָתַן עַל־כַּפֵּי הַנָּזִיר אַחַר הִתְגַּלְּחוֹ אֶת־נִזְרוֹ׃
וְהֵנִיף אוֹתָם הַכֹּהֵן תְּנוּפָה לִפְנֵי יְהוָה קֹדֶשׁ הוּא לַכֹּהֵן עַל חֲזֵה הַתְּנוּפָה וְעַל שׁוֹק הַתְּרוּמָה וְאַחַר יִשְׁתֶּה הַנָּזִיר יָיִן׃
זֹאת תּוֹרַת הַנָּזִיר אֲשֶׁר יִדֹּר קָרְבָּנוֹ לַיהוָה עַל־נִזְרוֹ מִלְּבַד אֲשֶׁר־תַּשִּׂיג יָדוֹ כְּפִי נִדְרוֹ אֲשֶׁר יִדֹּר כֵּן יַעֲשֶׂה עַל תּוֹרַת נִזְרוֹ׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־אַהֲרֹן וְאֶל־בָּנָיו לֵאמֹר כֹּה תְבָרֲכוּ אֶת־בְּנֵי יִשְׂרָאֵל אָמוֹר לָהֶם׃
יְבָרֶכְךָ יְהוָה וְיִשְׁמְרֶךָ׃
יָאֵר יְהוָה פָּנָיו אֵלֶיךָ וִיחֻנֶּךָּ׃
יִשָּׂא יְהוָה פָּנָיו אֵלֶיךָ וְיָשֵׂם לְךָ שָׁלוֹם׃
וְשָׂמוּ אֶת־שְׁמִי עַל־בְּנֵי יִשְׂרָאֵל וַאֲנִי אֲבָרֲכֵם׃

Chapter 7

וַיְהִי בְּיוֹם כַּלּוֹת מֹשֶׁה לְהָקִים אֶת־הַמִּשְׁכָּן וַיִּמְשַׁח אֹתוֹ וַיְקַדֵּשׁ אֹתוֹ וְאֶת־כָּל־כֵּלָיו וְאֶת־הַמִּזְבֵּחַ וְאֶת־כָּל־כֵּלָיו וַיִּמְשָׁחֵם וַיְקַדֵּשׁ אֹתָם׃
וַיַּקְרִיבוּ נְשִׂיאֵי יִשְׂרָאֵל רָאשֵׁי בֵּית אֲבֹתָם הֵם נְשִׂיאֵי הַמַּטֹּת הֵם הָעֹמְדִים עַל־הַפְּקֻדִים׃
וַיָּבִיאוּ אֶת־קָרְבָּנָם לִפְנֵי יְהוָה שֵׁשׁ־עֶגְלֹת צָב וּשְׁנֵי עָשָׂר בָּקָר עֲגָלָה עַל־שְׁנֵי הַנְּשִׂאִים וְשׁוֹר לְאֶחָד וַיַּקְרִיבוּ אוֹתָם לִפְנֵי הַמִּשְׁכָּן׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
קַח מֵאִתָּם וְהָיוּ לַעֲבֹד אֶת־עֲבֹדַת אֹהֶל מוֹעֵד וְנָתַתָּה אוֹתָם אֶל־הַלְוִיִּם אִישׁ כְּפִי עֲבֹדָתוֹ׃
וַיִּקַּח מֹשֶׁה אֶת־הָעֲגָלֹת וְאֶת־הַבָּקָר וַיִּתֵּן אוֹתָם אֶל־הַלְוִיִּם׃
אֵת שְׁתֵּי הָעֲגָלֹת וְאֵת אַרְבַּעַת הַבָּקָר נָתַן לִבְנֵי גֵרְשׁוֹן כְּפִי עֲבֹדָתָם׃
וְאֵת אַרְבַּע הָעֲגָלֹת וְאֵת שְׁמֹנַת הַבָּקָר נָתַן לִבְנֵי מְרָרִי כְּפִי עֲבֹדָתָם בְּיַד אִיתָמָר בֶּן־אַהֲרֹן הַכֹּהֵן׃
וְלִבְנֵי קְהָת לֹא נָתָן כִּי־עֲבֹדַת הַקֹּדֶשׁ עֲלֵהֶם בַּכָּתֵף יִשָּׂאוּ׃
וַיַּקְרִיבוּ הַנְּשִׂאִים אֵת חֲנֻכַּת הַמִּזְבֵּחַ בְּיוֹם הִמָּשַׁח אֹתוֹ וַיַּקְרִיבוּ הַנְּשִׂיאִם אֶת־קָרְבָּנָם לִפְנֵי הַמִּזְבֵּחַ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה נָשִׂיא אֶחָד לַיּוֹם נָשִׂיא אֶחָד לַיּוֹם יַקְרִיבוּ אֶת־קָרְבָּנָם לַחֲנֻכַּת הַמִּזְבֵּחַ׃
וַיְהִי הַמַּקְרִיב בַּיּוֹם הָרִאשׁוֹן אֶת־קָרְבָּנוֹ נַחְשׁוֹן בֶּן־עַמִּינָדָב לְמַטֵּה יְהוּדָה׃
וְקָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתּוּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן נַחְשׁוֹן בֶּן־עַמִּינָדָב׃
בַּיּוֹם הַשֵּׁנִי הִקְרִיב נְתַנְאֵל בֶּן־צוּעָר נְשִׂיא יִשָּׂשכָר׃
הִקְרִב אֶת־קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתּוּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן נְתַנְאֵל בֶּן־צוּעָר׃
בַּיּוֹם הַשְּׁלִישִׁי נָשִׂיא לִבְנֵי זְבוּלֻן אֱלִיאָב בֶּן־חֵלֹן׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן אֱלִיאָב בֶּן־חֵלֹן׃
בַּיּוֹם הָרְבִיעִי נָשִׂיא לִבְנֵי רְאוּבֵן אֱלִיצוּר בֶּן־שְׁדֵיאוּר׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן אֱלִיצוּר בֶּן־שְׁדֵיאוּר׃
בַּיּוֹם הַחֲמִישִׁי נָשִׂיא לִבְנֵי שִׁמְעוֹן שְׁלֻמִיאֵל בֶּן־צוּרִישַׁדָּי׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן שְׁלֻמִיאֵל בֶּן־צוּרִישַׁדָּי׃
בַּיּוֹם הַשִּׁשִּׁי נָשִׂיא לִבְנֵי גָד אֶלְיָסָף בֶּן־דְּעוּאֵל׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן אֶלְיָסָף בֶּן־דְּעוּאֵל׃
בַּיּוֹם הַשְּׁבִיעִי נָשִׂיא לִבְנֵי אֶפְרָיִם אֱלִישָׁמָע בֶּן־עַמִּיהוּד׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן אֱלִישָׁמָע בֶּן־עַמִּיהוּד׃
בַּיּוֹם הַשְּׁמִינִי נָשִׂיא לִבְנֵי מְנַשֶּׁה גַּמְלִיאֵל בֶּן־פְּדָה־צוּר׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן גַּמְלִיאֵל בֶּן־פְּדָה צוּר׃
בַּיּוֹם הַתְּשִׁיעִי נָשִׂיא לִבְנֵי בִנְיָמִן אֲבִידָן בֶּן־גִּדְעֹנִי׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן אֲבִידָן בֶּן־גִּדְעֹנִי׃
בַּיּוֹם הָעֲשִׂירִי נָשִׂיא לִבְנֵי דָן אֲחִיעֶזֶר בֶּן־עַמִּישַׁדָּי׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן אֲחִיעֶזֶר בֶּן־עַמִּישַׁדָּי׃
בְּיוֹם עַשְׁתֵּי עָשָׂר יוֹם נָשִׂיא לִבְנֵי אָשֵׁר פַּגְעִיאֵל בֶּן־עָכְרָן׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן פַּגְעִיאֵל בֶּן־עָכְרָן׃
בְּיוֹם שְׁנֵים עָשָׂר יוֹם נָשִׂיא לִבְנֵי נַפְתָּלִי אֲחִירַע בֶּן־עֵינָן׃
קָרְבָּנוֹ קַעֲרַת־כֶּסֶף אַחַת שְׁלֹשִׁים וּמֵאָה מִשְׁקָלָהּ מִזְרָק אֶחָד כֶּסֶף שִׁבְעִים שֶׁקֶל בְּשֶׁקֶל הַקֹּדֶשׁ שְׁנֵיהֶם מְלֵאִים סֹלֶת בְּלוּלָה בַשֶּׁמֶן לְמִנְחָה׃
כַּף אַחַת עֲשָׂרָה זָהָב מְלֵאָה קְטֹרֶת׃
פַּר אֶחָד בֶּן־בָּקָר אַיִל אֶחָד כֶּבֶשׂ־אֶחָד בֶּן־שְׁנָתוֹ לְעֹלָה׃
שְׂעִיר־עִזִּים אֶחָד לְחַטָּאת׃
וּלְזֶבַח הַשְּׁלָמִים בָּקָר שְׁנַיִם אֵילִם חֲמִשָּׁה עַתֻּדִים חֲמִשָּׁה כְּבָשִׂים בְּנֵי־שָׁנָה חֲמִשָּׁה זֶה קָרְבַּן אֲחִירַע בֶּן־עֵינָן׃
זֹאת חֲנֻכַּת הַמִּזְבֵּחַ בְּיוֹם הִמָּשַׁח אֹתוֹ מֵאֵת נְשִׂיאֵי יִשְׂרָאֵל קַעֲרֹת כֶּסֶף שְׁתֵּים עֶשְׂרֵה מִזְרְקֵי־כֶסֶף שְׁנֵים עָשָׂר כַּפּוֹת זָהָב שְׁתֵּים עֶשְׂרֵה׃
שְׁלֹשִׁים וּמֵאָה הַקְּעָרָה הָאַחַת כֶּסֶף וְשִׁבְעִים הַמִּזְרָק הָאֶחָד כֹּל כֶּסֶף הַכֵּלִים אַלְפַּיִם וְאַרְבַּע־מֵאוֹת בְּשֶׁקֶל הַקֹּדֶשׁ׃
כַּפּוֹת זָהָב שְׁתֵּים־עֶשְׂרֵה מְלֵאֹת קְטֹרֶת עֲשָׂרָה עֲשָׂרָה הַכַּף בְּשֶׁקֶל הַקֹּדֶשׁ כָּל־זְהַב הַכַּפּוֹת עֶשְׂרִים וּמֵאָה׃
כָּל־הַבָּקָר לָעֹלָה שְׁנֵים עָשָׂר פָּרִים אֵילִם שְׁנֵים־עָשָׂר כְּבָשִׂים בְּנֵי־שָׁנָה שְׁנֵים עָשָׂר וּמִנְחָתָם וּשְׂעִירֵי עִזִּים שְׁנֵים עָשָׂר לְחַטָּאת׃
וְכֹל בְּקַר זֶבַח הַשְּׁלָמִים עֶשְׂרִים וְאַרְבָּעָה פָּרִים אֵילִם שִׁשִּׁים עַתֻּדִים שִׁשִּׁים כְּבָשִׂים בְּנֵי־שָׁנָה שִׁשִּׁים זֹאת חֲנֻכַּת הַמִּזְבֵּחַ אַחֲרֵי הִמָּשַׁח אֹתוֹ׃
וּבְבֹא מֹשֶׁה אֶל־אֹהֶל מוֹעֵד לְדַבֵּר אִתּוֹ וַיִּשְׁמַע אֶת־הַקּוֹל מִדַּבֵּר אֵלָיו מֵעַל הַכַּפֹּרֶת אֲשֶׁר עַל־אֲרֹן הָעֵדֻת מִבֵּין שְׁנֵי הַכְּרֻבִים וַיְדַבֵּר אֵלָיו׃

Chapter 8

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־אַהֲרֹן וְאָמַרְתָּ אֵלָיו בְּהַעֲלֹתְךָ אֶת־הַנֵּרֹת אֶל־מוּל פְּנֵי הַמְּנוֹרָה יָאִירוּ שִׁבְעַת הַנֵּרוֹת׃
וַיַּעַשׂ כֵּן אַהֲרֹן אֶל־מוּל פְּנֵי הַמְּנוֹרָה הֶעֱלָה נֵרֹתֶיהָ כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וְזֶה מַעֲשֵׂה הַמְּנֹרָה מִקְשָׁה זָהָב עַד־יְרֵכָהּ עַד־פִּרְחָהּ מִקְשָׁה הִוא כַּמַּרְאֶה אֲשֶׁר הֶרְאָה יְהוָה אֶת־מֹשֶׁה כֵּן עָשָׂה אֶת־הַמְּנֹרָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
קַח אֶת־הַלְוִיִּם מִתּוֹךְ בְּנֵי יִשְׂרָאֵל וְטִהַרְתָּ אֹתָם׃
וְכֹה־תַעֲשֶׂה לָהֶם לְטַהֲרָם הַזֵּה עֲלֵיהֶם מֵי חַטָּאת וְהֶעֱבִירוּ תַעַר עַל־כָּל־בְּשָׂרָם וְכִבְּסוּ בִגְדֵיהֶם וְהִטֶּהָרוּ׃
וְלָקְחוּ פַּר בֶּן־בָּקָר וּמִנְחָתוֹ סֹלֶת בְּלוּלָה בַשָּׁמֶן וּפַר־שֵׁנִי בֶן־בָּקָר תִּקַּח לְחַטָּאת׃
וְהִקְרַבְתָּ אֶת־הַלְוִיִּם לִפְנֵי אֹהֶל מוֹעֵד וְהִקְהַלְתָּ אֶת־כָּל־עֲדַת בְּנֵי יִשְׂרָאֵל׃
וְהִקְרַבְתָּ אֶת־הַלְוִיִּם לִפְנֵי יְהוָה וְסָמְכוּ בְנֵי־יִשְׂרָאֵל אֶת־יְדֵיהֶם עַל־הַלְוִיִּם׃
וְהֵנִיף אַהֲרֹן אֶת־הַלְוִיִּם תְּנוּפָה לִפְנֵי יְהוָה מֵאֵת בְּנֵי יִשְׂרָאֵל וְהָיוּ לַעֲבֹד אֶת־עֲבֹדַת יְהוָה׃
וְהַלְוִיִּם יִסְמְכוּ אֶת־יְדֵיהֶם עַל רֹאשׁ הַפָּרִים וַעֲשֵׂה אֶת־הָאֶחָד חַטָּאת וְאֶת־הָאֶחָד עֹלָה לַיהוָה לְכַפֵּר עַל־הַלְוִיִּם׃
וְהַעֲמַדְתָּ אֶת־הַלְוִיִּם לִפְנֵי אַהֲרֹן וְלִפְנֵי בָנָיו וְהֵנַפְתָּ אֹתָם תְּנוּפָה לַיהוָה׃
וְהִבְדַּלְתָּ אֶת־הַלְוִיִּם מִתּוֹךְ בְּנֵי יִשְׂרָאֵל וְהָיוּ לִי הַלְוִיִּם׃
וְאַחֲרֵי־כֵן יָבֹאוּ הַלְוִיִּם לַעֲבֹד אֶת־אֹהֶל מוֹעֵד וְטִהַרְתָּ אֹתָם וְהֵנַפְתָּ אֹתָם תְּנוּפָה׃
כִּי נְתֻנִים נְתֻנִים הֵמָּה לִי מִתּוֹךְ בְּנֵי יִשְׂרָאֵל תַּחַת פִּטְרַת כָּל־רֶחֶם בְּכוֹר כֹּל מִבְּנֵי יִשְׂרָאֵל לָקַחְתִּי אֹתָם לִי׃
כִּי לִי כָל־בְּכוֹר בִּבְנֵי יִשְׂרָאֵל בָּאָדָם וּבַבְּהֵמָה בְּיוֹם הַכֹּתִי כָל־בְּכוֹר בְּאֶרֶץ מִצְרַיִם הִקְדַּשְׁתִּי אֹתָם לִי׃
וָאֶקַּח אֶת־הַלְוִיִּם תַּחַת כָּל־בְּכוֹר בִּבְנֵי יִשְׂרָאֵל׃
וָאֶתְּנָה אֶת־הַלְוִיִּם נְתֻנִים לְאַהֲרֹן וּלְבָנָיו מִתּוֹךְ בְּנֵי יִשְׂרָאֵל לַעֲבֹד אֶת־עֲבֹדַת בְּנֵי־יִשְׂרָאֵל בְּאֹהֶל מוֹעֵד וּלְכַפֵּר עַל־בְּנֵי יִשְׂרָאֵל וְלֹא יִהְיֶה בִּבְנֵי יִשְׂרָאֵל נֶגֶף בְּגֶשֶׁת בְּנֵי־יִשְׂרָאֵל אֶל־הַקֹּדֶשׁ׃
וַיַּעַשׂ מֹשֶׁה וְאַהֲרֹן וְכָל־עֲדַת בְּנֵי־יִשְׂרָאֵל לַלְוִיִּם כְּכֹל אֲשֶׁר־צִוָּה יְהוָה אֶת־מֹשֶׁה לַלְוִיִּם כֵּן־עָשׂוּ לָהֶם בְּנֵי יִשְׂרָאֵל׃
וַיִּתְחַטְּאוּ הַלְוִיִּם וַיְכַבְּסוּ בִּגְדֵיהֶם וַיָּנֶף אַהֲרֹן אֹתָם תְּנוּפָה לִפְנֵי יְהוָה וַיְכַפֵּר עֲלֵיהֶם אַהֲרֹן לְטַהֲרָם׃
וְאַחֲרֵי־כֵן בָּאוּ הַלְוִיִּם לַעֲבֹד אֶת־עֲבֹדָתָם בְּאֹהֶל מוֹעֵד לִפְנֵי אַהֲרֹן וְלִפְנֵי בָנָיו כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה עַל־הַלְוִיִּם כֵּן עָשׂוּ לָהֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
זֹאת אֲשֶׁר לַלְוִיִּם מִבֶּן חָמֵשׁ וְעֶשְׂרִים שָׁנָה וָמַעְלָה יָבוֹא לִצְבֹא צָבָא בַּעֲבֹדַת אֹהֶל מוֹעֵד׃
וּמִבֶּן חֲמִשִּׁים שָׁנָה יָשׁוּב מִצְּבָא הָעֲבֹדָה וְלֹא יַעֲבֹד עוֹד׃
וְשֵׁרֵת אֶת־אֶחָיו בְּאֹהֶל מוֹעֵד לִשְׁמֹר מִשְׁמֶרֶת וַעֲבֹדָה לֹא יַעֲבֹד כָּכָה תַּעֲשֶׂה לַלְוִיִּם בְּמִשְׁמְרֹתָם׃

Chapter 9

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה בְמִדְבַּר־סִינַי בַּשָּׁנָה הַשֵּׁנִית לְצֵאתָם מֵאֶרֶץ מִצְרַיִם בַּחֹדֶשׁ הָרִאשׁוֹן לֵאמֹר׃
וְיַעֲשׂוּ בְנֵי־יִשְׂרָאֵל אֶת־הַפָּסַח בְּמוֹעֲדוֹ׃
בְּאַרְבָּעָה עָשָׂר־יוֹם בַּחֹדֶשׁ הַזֶּה בֵּין הָעֲרְבַּיִם תַּעֲשׂוּ אֹתוֹ בְּמוֹעֲדוֹ כְּכָל־חֻקֹּתָיו וּכְכָל־מִשְׁפָּטָיו תַּעֲשׂוּ אֹתוֹ׃
וַיְדַבֵּר מֹשֶׁה אֶל־בְּנֵי יִשְׂרָאֵל לַעֲשֹׂת הַפָּסַח׃
וַיַּעֲשׂוּ אֶת־הַפֶּסַח בָּרִאשׁוֹן בְּאַרְבָּעָה עָשָׂר יוֹם לַחֹדֶשׁ בֵּין הָעַרְבַּיִם בְּמִדְבַּר סִינָי כְּכֹל אֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה כֵּן עָשׂוּ בְּנֵי יִשְׂרָאֵל׃
וַיְהִי אֲנָשִׁים אֲשֶׁר הָיוּ טְמֵאִים לְנֶפֶשׁ אָדָם וְלֹא־יָכְלוּ לַעֲשֹׂת־הַפֶּסַח בַּיּוֹם הַהוּא וַיִּקְרְבוּ לִפְנֵי מֹשֶׁה וְלִפְנֵי אַהֲרֹן בַּיּוֹם הַהוּא׃
וַיֹּאמְרוּ הָאֲנָשִׁים הָהֵמָּה אֵלָיו אֲנַחְנוּ טְמֵאִים לְנֶפֶשׁ אָדָם לָמָּה נִגָּרַע לְבִלְתִּי הַקְרִב אֶת־קָרְבַּן יְהוָה בְּמֹעֲדוֹ בְּתוֹךְ בְּנֵי יִשְׂרָאֵל׃
וַיֹּאמֶר אֲלֵהֶם מֹשֶׁה עִמְדוּ וְאֶשְׁמְעָה מַה־יְצַוֶּה יְהוָה לָכֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר אִישׁ אִישׁ כִּי־יִהְיֶה־טָמֵא לָנֶפֶשׁ אוֹ בְדֶרֶךְ רְחֹקָה לָכֶם אוֹ לְדֹרֹתֵיכֶם וְעָשָׂה פֶסַח לַיהוָה׃
בַּחֹדֶשׁ הַשֵּׁנִי בְּאַרְבָּעָה עָשָׂר יוֹם בֵּין הָעַרְבַּיִם יַעֲשׂוּ אֹתוֹ עַל־מַצּוֹת וּמְרֹרִים יֹאכְלֻהוּ׃
לֹא־יַשְׁאִירוּ מִמֶּנּוּ עַד־בֹּקֶר וְעֶצֶם לֹא יִשְׁבְּרוּ־בוֹ כְּכָל־חֻקַּת הַפֶּסַח יַעֲשׂוּ אֹתוֹ׃
וְהָאִישׁ אֲשֶׁר־הוּא טָהוֹר וּבְדֶרֶךְ לֹא־הָיָה וְחָדַל לַעֲשׂוֹת הַפֶּסַח וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מֵעַמֶּיהָ כִּי קָרְבַּן יְהוָה לֹא הִקְרִיב בְּמֹעֲדוֹ חֶטְאוֹ יִשָּׂא הָאִישׁ הַהוּא׃
וְכִי־יָגוּר אִתְּכֶם גֵּר וְעָשָׂה פֶסַח לַיהוָה כְּחֻקַּת הַפֶּסַח וּכְמִשְׁפָּטוֹ כֵּן יַעֲשֶׂה חֻקָּה אַחַת יִהְיֶה לָכֶם וְלַגֵּר וּלְאֶזְרַח הָאָרֶץ׃
וּבְיוֹם הָקִים אֶת־הַמִּשְׁכָּן כִּסָּה הֶעָנָן אֶת־הַמִּשְׁכָּן לְאֹהֶל הָעֵדֻת וּבָעֶרֶב יִהְיֶה עַל־הַמִּשְׁכָּן כְּמַרְאֵה־אֵשׁ עַד־בֹּקֶר׃
כֵּן יִהְיֶה תָמִיד הֶעָנָן יְכַסֶּנּוּ וּמַרְאֵה־אֵשׁ לָיְלָה׃
וּלְפִי הֵעָלֹת הֶעָנָן מֵעַל הָאֹהֶל וְאַחֲרֵי־כֵן יִסְעוּ בְּנֵי יִשְׂרָאֵל וּבִמְקוֹם אֲשֶׁר יִשְׁכָּן־שָׁם הֶעָנָן שָׁם יַחֲנוּ בְּנֵי יִשְׂרָאֵל׃
עַל־פִּי יְהוָה יִסְעוּ בְּנֵי יִשְׂרָאֵל וְעַל־פִּי יְהוָה יַחֲנוּ כָּל־יְמֵי אֲשֶׁר יִשְׁכֹּן הֶעָנָן עַל־הַמִּשְׁכָּן יַחֲנוּ׃
וּבְהַאֲרִיךְ הֶעָנָן עַל־הַמִּשְׁכָּן יָמִים רַבִּים וְשָׁמְרוּ בְנֵי־יִשְׂרָאֵל אֶת־מִשְׁמֶרֶת יְהוָה וְלֹא יִסָּעוּ׃
וְיֵשׁ אֲשֶׁר יִהְיֶה הֶעָנָן יָמִים מִסְפָּר עַל־הַמִּשְׁכָּן עַל־פִּי יְהוָה יַחֲנוּ וְעַל־פִּי יְהוָה יִסָּעוּ׃
וְיֵשׁ אֲשֶׁר־יִהְיֶה הֶעָנָן מֵעֶרֶב עַד־בֹּקֶר וְנַעֲלָה הֶעָנָן בַּבֹּקֶר וְנָסָעוּ אוֹ יוֹמָם וָלַיְלָה וְנַעֲלָה הֶעָנָן וְנָסָעוּ׃
אוֹ־יֹמַיִם אוֹ־חֹדֶשׁ אוֹ־יָמִים בְּהַאֲרִיךְ הֶעָנָן עַל־הַמִּשְׁכָּן לִשְׁכֹּן עָלָיו יַחֲנוּ בְנֵי־יִשְׂרָאֵל וְלֹא יִסָּעוּ וּבְהֵעָלֹתוֹ יִסָּעוּ׃
עַל־פִּי יְהוָה יַחֲנוּ וְעַל־פִּי יְהוָה יִסָּעוּ אֶת־מִשְׁמֶרֶת יְהוָה שָׁמָרוּ עַל־פִּי יְהוָה בְּיַד־מֹשֶׁה׃

Chapter 10

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
עֲשֵׂה לְךָ שְׁתֵּי חֲצוֹצְרֹת כֶּסֶף מִקְשָׁה תַּעֲשֶׂה אֹתָם וְהָיוּ לְךָ לְמִקְרָא הָעֵדָה וּלְמַסַּע אֶת־הַמַּחֲנוֹת׃
וְתָקְעוּ בָּהֵן וְנוֹעֲדוּ אֵלֶיךָ כָּל־הָעֵדָה אֶל־פֶּתַח אֹהֶל מוֹעֵד׃
וְאִם־בְּאַחַת יִתְקָעוּ וְנוֹעֲדוּ אֵלֶיךָ הַנְּשִׂיאִים רָאשֵׁי אַלְפֵי יִשְׂרָאֵל׃
וּתְקַעְתֶּם תְּרוּעָה וְנָסְעוּ הַמַּחֲנוֹת הַחֹנִים קֵדְמָה׃
וּתְקַעְתֶּם תְּרוּעָה שֵׁנִית וְנָסְעוּ הַמַּחֲנוֹת הַחֹנִים תֵּימָנָה תְּרוּעָה יִתְקְעוּ לְמַסְעֵיהֶם׃
וּבְהַקְהִיל אֶת־הַקָּהָל תִּתְקְעוּ וְלֹא תָרִיעוּ׃
וּבְנֵי אַהֲרֹן הַכֹּהֲנִים יִתְקְעוּ בַּחֲצֹצְרוֹת וְהָיוּ לָכֶם לְחֻקַּת עוֹלָם לְדֹרֹתֵיכֶם׃
וְכִי־תָבֹאוּ מִלְחָמָה בְּאַרְצְכֶם עַל־הַצַּר הַצֹּרֵר אֶתְכֶם וַהֲרֵעֹתֶם בַּחֲצֹצְרוֹת וֲנִזְכַּרְתֶּם לִפְנֵי יְהוָה אֱלֹהֵיכֶם וְנוֹשַׁעְתֶּם מֵאֹיְבֵיכֶם׃
וּבְיוֹם שִׂמְחַתְכֶם וּבְמוֹעֲדֵיכֶם וּבְרָאשֵׁי חָדְשֵׁיכֶם וּתְקַעְתֶּם בַּחֲצֹצְרֹת עַל עֹלֹתֵיכֶם וְעַל זִבְחֵי שַׁלְמֵיכֶם וְהָיוּ לָכֶם לְזִכָּרוֹן לִפְנֵי אֱלֹהֵיכֶם אֲנִי יְהוָה אֱלֹהֵיכֶם׃
וַיְהִי בַּשָּׁנָה הַשֵּׁנִית בַּחֹדֶשׁ הַשֵּׁנִי בְּעֶשְׂרִים בַּחֹדֶשׁ נַעֲלָה הֶעָנָן מֵעַל מִשְׁכַּן הָעֵדֻת׃
וַיִּסְעוּ בְנֵי־יִשְׂרָאֵל לְמַסְעֵיהֶם מִמִּדְבַּר סִינָי וַיִּשְׁכֹּן הֶעָנָן בְּמִדְבַּר פָּארָן׃
וַיִּסְעוּ בָּרִאשֹׁנָה עַל־פִּי יְהוָה בְּיַד־מֹשֶׁה׃
וַיִּסַּע דֶּגֶל מַחֲנֵה בְנֵי־יְהוּדָה בָּרִאשֹׁנָה לְצִבְאֹתָם וְעַל־צְבָאוֹ נַחְשׁוֹן בֶּן־עַמִּינָדָב׃
וְעַל־צְבָא מַטֵּה בְּנֵי יִשָׂשכָר נְתַנְאֵל בֶּן־צוּעָר׃
וְעַל־צְבָא מַטֵּה בְּנֵי זְבוּלֻן אֱלִיאָב בֶּן־חֵלוֹן׃
וְהוּרַד הַמִּשְׁכָּן וְנָסְעוּ בְנֵי־גֵרְשׁוֹן וּבְנֵי מְרָרִי נֹשְׂאֵי הַמִּשְׁכָּן׃
וְנָסַע דֶּגֶל מַחֲנֵה רְאוּבֵן לְצִבְאֹתָם וְעַל־צְבָאוֹ אֱלִיצוּר בֶּן־שְׁדֵיאוּר׃
וְעַל־צְבָא מַטֵּה בְּנֵי שִׁמְעוֹן שְׁלֻמִיאֵל בֶּן־צוּרִי שַׁדָּי׃
וְעַל־צְבָא מַטֵּה בְנֵי־גָד אֶלְיָסָף בֶּן־דְּעוּאֵל׃
וְנָסְעוּ הַקְּהָתִים נֹשְׂאֵי הַמִּקְדָּשׁ וְהֵקִימוּ אֶת־הַמִּשְׁכָּן עַד־בֹּאָם׃
וְנָסַע דֶּגֶל מַחֲנֵה בְנֵי־אֶפְרַיִם לְצִבְאֹתָם וְעַל־צְבָאוֹ אֱלִישָׁמָע בֶּן־עַמִּיהוּד׃
וְעַל־צְבָא מַטֵּה בְּנֵי מְנַשֶּׁה גַּמְלִיאֵל בֶּן־פְּדָה־צוּר׃
וְעַל־צְבָא מַטֵּה בְּנֵי בִנְיָמִן אֲבִידָן בֶּן־גִּדְעוֹנִי׃
וְנָסַע דֶּגֶל מַחֲנֵה בְנֵי־דָן מְאַסֵּף לְכָל־הַמַּחֲנֹת לְצִבְאֹתָם וְעַל־צְבָאוֹ אֲחִיעֶזֶר בֶּן־עַמִּישַׁדָּי׃
וְעַל־צְבָא מַטֵּה בְּנֵי אָשֵׁר פַּגְעִיאֵל בֶּן־עָכְרָן׃
וְעַל־צְבָא מַטֵּה בְּנֵי נַפְתָּלִי אֲחִירַע בֶּן־עֵינָן׃
אֵלֶּה מַסְעֵי בְנֵי־יִשְׂרָאֵל לְצִבְאֹתָם וַיִּסָּעוּ׃
וַיֹּאמֶר מֹשֶׁה לְחֹבָב בֶּן־רְעוּאֵל הַמִּדְיָנִי חֹתֵן מֹשֶׁה נֹסְעִים אֲנַחְנוּ אֶל־הַמָּקוֹם אֲשֶׁר אָמַר יְהוָה אֹתוֹ אֶתֵּן לָכֶם לְכָה אִתָּנוּ וְהֵטַבְנוּ לָךְ כִּי־יְהוָה דִּבֶּר־טוֹב עַל־יִשְׂרָאֵל׃
וַיֹּאמֶר אֵלָיו לֹא אֵלֵךְ כִּי אִם־אֶל־אַרְצִי וְאֶל־מוֹלַדְתִּי אֵלֵךְ׃
וַיֹּאמֶר אַל־נָא תַּעֲזֹב אֹתָנוּ כִּי עַל־כֵּן יָדַעְתָּ חֲנֹתֵנוּ בַּמִּדְבָּר וְהָיִיתָ לָּנוּ לְעֵינָיִם׃
וְהָיָה כִּי־תֵלֵךְ עִמָּנוּ וְהָיָה הַטּוֹב הַהוּא אֲשֶׁר יֵיטִיב יְהוָה עִמָּנוּ וְהֵטַבְנוּ לָךְ׃
וַיִּסְעוּ מֵהַר יְהוָה דֶּרֶךְ שְׁלֹשֶׁת יָמִים וַאֲרוֹן בְּרִית־יְהוָה נֹסֵעַ לִפְנֵיהֶם דֶּרֶךְ שְׁלֹשֶׁת יָמִים לָתוּר לָהֶם מְנוּחָה׃
וַעֲנַן יְהוָה עֲלֵיהֶם יוֹמָם בְּנָסְעָם מִן־הַמַּחֲנֶה׃
וַיְהִי בִּנְסֹעַ הָאָרֹן וַיֹּאמֶר מֹשֶׁה קוּמָה יְהוָה וְיָפֻצוּ אֹיְבֶיךָ וְיָנֻסוּ מְשַׂנְאֶיךָ מִפָּנֶיךָ׃
וּבְנֻחֹה יֹאמַר שׁוּבָה יְהוָה רִבְבוֹת אַלְפֵי יִשְׂרָאֵל׃

Chapter 11

וַיְהִי הָעָם כְּמִתְאֹנְנִים רַע בְּאָזְנֵי יְהוָה וַיִּשְׁמַע יְהוָה וַיִּחַר אַפּוֹ וַתִּבְעַר־בָּם אֵשׁ יְהוָה וַתֹּאכַל בִּקְצֵה הַמַּחֲנֶה׃
וַיִּצְעַק הָעָם אֶל־מֹשֶׁה וַיִּתְפַּלֵּל מֹשֶׁה אֶל־יְהוָה וַתִּשְׁקַע הָאֵשׁ׃
וַיִּקְרָא שֵׁם־הַמָּקוֹם הַהוּא תַּבְעֵרָה כִּי־בָעֲרָה בָם אֵשׁ יְהוָה׃
וְהָאסַפְסֻף אֲשֶׁר בְּקִרְבּוֹ הִתְאַוּוּ תַּאֲוָה וַיָּשֻׁבוּ וַיִּבְכּוּ גַּם בְּנֵי יִשְׂרָאֵל וַיֹּאמְרוּ מִי יַאֲכִלֵנוּ בָּשָׂר׃
זָכַרְנוּ אֶת־הַדָּגָה אֲשֶׁר־נֹאכַל בְּמִצְרַיִם חִנָּם אֵת הַקִּשֻּׁאִים וְאֵת הָאֲבַטִּחִים וְאֶת־הֶחָצִיר וְאֶת־הַבְּצָלִים וְאֶת־הַשּׁוּמִים׃
וְעַתָּה נַפְשֵׁנוּ יְבֵשָׁה אֵין כֹּל בִּלְתִּי אֶל־הַמָּן עֵינֵינוּ׃
וְהַמָּן כִּזְרַע־גַּד הוּא וְעֵינוֹ כְּעֵין הַבְּדֹלַח׃
שָׁטוּ הָעָם וְלָקְטוּ וְטָחֲנוּ בָרֵחַיִם אוֹ דָכוּ בַּמְּדֹכָה וּבִשְּׁלוּ בַּפָּרוּר וְעָשׂוּ אֹתוֹ עֻגוֹת וְהָיָה טַעְמוֹ כְּטַעַם לְשַׁד הַשָּׁמֶן׃
וּבְרֶדֶת הַטַּל עַל־הַמַּחֲנֶה לָיְלָה יֵרֵד הַמָּן עָלָיו׃
וַיִּשְׁמַע מֹשֶׁה אֶת־הָעָם בֹּכֶה לְמִשְׁפְּחֹתָיו אִישׁ לְפֶתַח אָהֳלוֹ וַיִּחַר־אַף יְהוָה מְאֹד וּבְעֵינֵי מֹשֶׁה רָע׃
וַיֹּאמֶר מֹשֶׁה אֶל־יְהוָה לָמָה הֲרֵעֹתָ לְעַבְדֶּךָ וְלָמָּה לֹא־מָצָתִי חֵן בְּעֵינֶיךָ לָשׂוּם אֶת־מַשָּׂא כָּל־הָעָם הַזֶּה עָלָי׃
הֶאָנֹכִי הָרִיתִי אֵת כָּל־הָעָם הַזֶּה אִם־אָנֹכִי יְלִדְתִּיהוּ כִּי־תֹאמַר אֵלַי שָׂאֵהוּ בְחֵיקֶךָ כַּאֲשֶׁר יִשָּׂא הָאֹמֵן אֶת־הַיֹּנֵק עַל הָאֲדָמָה אֲשֶׁר נִשְׁבַּעְתָּ לַאֲבֹתָיו׃
מֵאַיִן לִי בָּשָׂר לָתֵת לְכָל־הָעָם הַזֶּה כִּי־יִבְכּוּ עָלַי לֵאמֹר תְּנָה־לָּנוּ בָשָׂר וְנֹאכֵלָה׃
לֹא־אוּכַל אָנֹכִי לְבַדִּי לָשֵׂאת אֶת־כָּל־הָעָם הַזֶּה כִּי כָבֵד מִמֶּנִּי׃
וְאִם־כָּכָה אַתְּ־עֹשֶׂה לִּי הָרְגֵנִי נָא הָרֹג אִם־מָצָאתִי חֵן בְּעֵינֶיךָ וְאַל־אֶרְאֶה בְּרָעָתִי׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה אֶסְפָה־לִּי שִׁבְעִים אִישׁ מִזִּקְנֵי יִשְׂרָאֵל אֲשֶׁר יָדַעְתָּ כִּי־הֵם זִקְנֵי הָעָם וְשֹׁטְרָיו וְלָקַחְתָּ אֹתָם אֶל־אֹהֶל מוֹעֵד וְהִתְיַצְּבוּ שָׁם עִמָּךְ׃
וְיָרַדְתִּי וְדִבַּרְתִּי עִמְּךָ שָׁם וְאָצַלְתִּי מִן־הָרוּחַ אֲשֶׁר עָלֶיךָ וְשַׂמְתִּי עֲלֵיהֶם וְנָשְׂאוּ אִתְּךָ בְּמַשָּׂא הָעָם וְלֹא־תִשָּׂא אַתָּה לְבַדֶּךָ׃
וְאֶל־הָעָם תֹּאמַר הִתְקַדְּשׁוּ לְמָחָר וַאֲכַלְתֶּם בָּשָׂר כִּי בְּכִיתֶם בְּאָזְנֵי יְהוָה לֵאמֹר מִי יַאֲכִלֵנוּ בָּשָׂר כִּי־טוֹב לָנוּ בְּמִצְרָיִם וְנָתַן יְהוָה לָכֶם בָּשָׂר וַאֲכַלְתֶּם׃
לֹא יוֹם אֶחָד תֹּאכְלוּן וְלֹא יוֹמָיִם וְלֹא חֲמִשָּׁה יָמִים וְלֹא עֲשָׂרָה יָמִים וְלֹא עֶשְׂרִים יוֹם׃
עַד חֹדֶשׁ יָמִים עַד אֲשֶׁר־יֵצֵא מֵאַפְּכֶם וְהָיָה לָכֶם לְזָרָא יַעַן כִּי־מְאַסְתֶּם אֶת־יְהוָה אֲשֶׁר בְּקִרְבְּכֶם וַתִּבְכּוּ לְפָנָיו לֵאמֹר לָמָּה זֶּה יָצָאנוּ מִמִּצְרָיִם׃
וַיֹּאמֶר מֹשֶׁה שֵׁשׁ־מֵאוֹת אֶלֶף רַגְלִי הָעָם אֲשֶׁר אָנֹכִי בְּקִרְבּוֹ וְאַתָּה אָמַרְתָּ בָּשָׂר אֶתֵּן לָהֶם וְאָכְלוּ חֹדֶשׁ יָמִים׃
הֲצֹאן וּבָקָר יִשָּׁחֵט לָהֶם וּמָצָא לָהֶם אִם אֶת־כָּל־דְּגֵי הַיָּם יֵאָסֵף לָהֶם וּמָצָא לָהֶם׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה הֲיַד יְהוָה תִּקְצָר עַתָּה תִרְאֶה הֲיִקְרְךָ דְבָרִי אִם־לֹא׃
וַיֵּצֵא מֹשֶׁה וַיְדַבֵּר אֶל־הָעָם אֵת דִּבְרֵי יְהוָה וַיֶּאֱסֹף שִׁבְעִים אִישׁ מִזִּקְנֵי הָעָם וַיַּעֲמֵד אֹתָם סְבִיבֹת הָאֹהֶל׃
וַיֵּרֶד יְהוָה בֶּעָנָן וַיְדַבֵּר אֵלָיו וַיָּאצֶל מִן־הָרוּחַ אֲשֶׁר עָלָיו וַיִּתֵּן עַל־שִׁבְעִים אִישׁ הַזְּקֵנִים וַיְהִי כְּנוֹחַ עֲלֵיהֶם הָרוּחַ וַיִּתְנַבְּאוּ וְלֹא יָסָפוּ׃
וַיִּשָּׁאֲרוּ שְׁנֵי־אֲנָשִׁים בַּמַּחֲנֶה שֵׁם הָאֶחָד אֶלְדָּד וְשֵׁם הַשֵּׁנִי מֵידָד וַתָּנַח עֲלֵיהֶם הָרוּחַ וְהֵמָּה בַּכְּתֻבִים וְלֹא יָצְאוּ הָאֹהֱלָה וַיִּתְנַבְּאוּ בַּמַּחֲנֶה׃
וַיָּרָץ הַנַּעַר וַיַּגֵּד לְמֹשֶׁה וַיֹּאמַר אֶלְדָּד וּמֵידָד מִתְנַבְּאִים בַּמַּחֲנֶה׃
וַיַּעַן יְהוֹשֻׁעַ בִּן־נוּן מְשָׁרֵת מֹשֶׁה מִבְּחֻרָיו וַיֹּאמַר אֲדֹנִי מֹשֶׁה כְּלָאֵם׃
וַיֹּאמֶר לוֹ מֹשֶׁה הַמְקַנֵּא אַתָּה לִי וּמִי יִתֵּן כָּל־עַם יְהוָה נְבִיאִים כִּי־יִתֵּן יְהוָה אֶת־רוּחוֹ עֲלֵיהֶם׃
וַיֵּאָסֵף מֹשֶׁה אֶל־הַמַּחֲנֶה הוּא וְזִקְנֵי יִשְׂרָאֵל׃
וְרוּחַ נָסַע מֵאֵת יְהוָה וַיָּגָז שַׂלְוִים מִן־הַיָּם וַיִּטֹּשׁ עַל־הַמַּחֲנֶה כְּדֶרֶךְ יוֹם כֹּה וּכְדֶרֶךְ יוֹם כֹּה סְבִיבוֹת הַמַּחֲנֶה וּכְאַמָּתַיִם עַל־פְּנֵי הָאָרֶץ׃
וַיָּקָם הָעָם כָּל־הַיּוֹם הַהוּא וְכָל־הַלַּיְלָה וְכֹל יוֹם הַמָּחֳרָת וַיַּאַסְפוּ אֶת־הַשְּׂלָו הַמַּמְעִיט אָסַף עֲשָׂרָה חֳמָרִים וַיִּשְׁטְחוּ לָהֶם שָׁטוֹחַ סְבִיבוֹת הַמַּחֲנֶה׃
הַבָּשָׂר עוֹדֶנּוּ בֵּין שִׁנֵּיהֶם טֶרֶם יִכָּרֵת וְאַף יְהוָה חָרָה בָעָם וַיַּךְ יְהוָה בָּעָם מַכָּה רַבָּה מְאֹד׃
וַיִּקְרָא אֶת־שֵׁם־הַמָּקוֹם הַהוּא קִבְרוֹת הַתַּאֲוָה כִּי־שָׁם קָבְרוּ אֶת־הָעָם הַמִּתְאַוִּים׃
מִקִּבְרוֹת הַתַּאֲוָה נָסְעוּ הָעָם חֲצֵרוֹת וַיִּהְיוּ בַּחֲצֵרוֹת׃

Chapter 12

וַתְּדַבֵּר מִרְיָם וְאַהֲרֹן בְּמֹשֶׁה עַל־אֹדוֹת הָאִשָּׁה הַכֻּשִׁית אֲשֶׁר לָקָח כִּי־אִשָּׁה כֻשִׁית לָקָח׃
וַיֹּאמְרוּ הֲרַק אַךְ־בְּמֹשֶׁה דִּבֶּר יְהוָה הֲלֹא גַּם־בָּנוּ דִבֵּר וַיִּשְׁמַע יְהוָה׃
וְהָאִישׁ מֹשֶׁה ענו [עָנָיו] מְאֹד מִכֹּל הָאָדָם אֲשֶׁר עַל־פְּנֵי הָאֲדָמָה׃
וַיֹּאמֶר יְהוָה פִּתְאֹם אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן וְאֶל־מִרְיָם צְאוּ שְׁלָשְׁתְּכֶם אֶל־אֹהֶל מוֹעֵד וַיֵּצְאוּ שְׁלָשְׁתָּם׃
וַיֵּרֶד יְהוָה בְּעַמּוּד עָנָן וַיַּעֲמֹד פֶּתַח הָאֹהֶל וַיִּקְרָא אַהֲרֹן וּמִרְיָם וַיֵּצְאוּ שְׁנֵיהֶם׃
וַיֹּאמֶר שִׁמְעוּ־נָא דְבָרָי אִם־יִהְיֶה נְבִיאֲכֶם יְהוָה בַּמַּרְאָה אֵלָיו אֶתְוַדָּע בַּחֲלוֹם אֲדַבֶּר־בּוֹ׃
לֹא־כֵן עַבְדִּי מֹשֶׁה בְּכָל־בֵּיתִי נֶאֱמָן הוּא׃
פֶּה אֶל־פֶּה אֲדַבֶּר־בּוֹ וּמַרְאֶה וְלֹא בְחִידֹת וּתְמֻנַת יְהוָה יַבִּיט וּמַדּוּעַ לֹא יְרֵאתֶם לְדַבֵּר בְּעַבְדִּי בְמֹשֶׁה׃
וַיִּחַר אַף יְהוָה בָּם וַיֵּלַךְ׃
וְהֶעָנָן סָר מֵעַל הָאֹהֶל וְהִנֵּה מִרְיָם מְצֹרַעַת כַּשָּׁלֶג וַיִּפֶן אַהֲרֹן אֶל־מִרְיָם וְהִנֵּה מְצֹרָעַת׃
וַיֹּאמֶר אַהֲרֹן אֶל־מֹשֶׁה בִּי אֲדֹנִי אַל־נָא תָשֵׁת עָלֵינוּ חַטָּאת אֲשֶׁר נוֹאַלְנוּ וַאֲשֶׁר חָטָאנוּ׃
אַל־נָא תְהִי כַּמֵּת אֲשֶׁר בְּצֵאתוֹ מֵרֶחֶם אִמּוֹ וַיֵּאָכֵל חֲצִי בְשָׂרוֹ׃
וַיִּצְעַק מֹשֶׁה אֶל־יְהוָה לֵאמֹר אֵל נָא רְפָא נָא לָהּ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאָבִיהָ יָרֹק יָרַק בְּפָנֶיהָ הֲלֹא תִכָּלֵם שִׁבְעַת יָמִים תִּסָּגֵר שִׁבְעַת יָמִים מִחוּץ לַמַּחֲנֶה וְאַחַר תֵּאָסֵף׃
וַתִּסָּגֵר מִרְיָם מִחוּץ לַמַּחֲנֶה שִׁבְעַת יָמִים וְהָעָם לֹא נָסַע עַד־הֵאָסֵף מִרְיָם׃
וְאַחַר נָסְעוּ הָעָם מֵחֲצֵרוֹת וַיַּחֲנוּ בְּמִדְבַּר פָּארָן׃

Chapter 13

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
שְׁלַח־לְךָ אֲנָשִׁים וְיָתֻרוּ אֶת־אֶרֶץ כְּנַעַן אֲשֶׁר־אֲנִי נֹתֵן לִבְנֵי יִשְׂרָאֵל אִישׁ אֶחָד אִישׁ אֶחָד לְמַטֵּה אֲבֹתָיו תִּשְׁלָחוּ כֹּל נָשִׂיא בָהֶם׃
וַיִּשְׁלַח אֹתָם מֹשֶׁה מִמִּדְבַּר פָּארָן עַל־פִּי יְהוָה כֻּלָּם אֲנָשִׁים רָאשֵׁי בְנֵי־יִשְׂרָאֵל הֵמָּה׃
וְאֵלֶּה שְׁמוֹתָם לְמַטֵּה רְאוּבֵן שַׁמּוּעַ בֶּן־זַכּוּר׃
לְמַטֵּה שִׁמְעוֹן שָׁפָט בֶּן־חוֹרִי׃
לְמַטֵּה יְהוּדָה כָּלֵב בֶּן־יְפֻנֶּה׃
לְמַטֵּה יִשָּׂשכָר יִגְאָל בֶּן־יוֹסֵף׃
לְמַטֵּה אֶפְרָיִם הוֹשֵׁעַ בִּן־נוּן׃
לְמַטֵּה בִנְיָמִן פַּלְטִי בֶּן־רָפוּא׃
לְמַטֵּה זְבוּלֻן גַּדִּיאֵל בֶּן־סוֹדִי׃
לְמַטֵּה יוֹסֵף לְמַטֵּה מְנַשֶּׁה גַּדִּי בֶּן־סוּסִי׃
לְמַטֵּה דָן עַמִּיאֵל בֶּן־גְּמַלִּי׃
לְמַטֵּה אָשֵׁר סְתוּר בֶּן־מִיכָאֵל׃
לְמַטֵּה נַפְתָּלִי נַחְבִּי בֶּן־וָפְסִי׃
לְמַטֵּה גָד גְּאוּאֵל בֶּן־מָכִי׃
אֵלֶּה שְׁמוֹת הָאֲנָשִׁים אֲשֶׁר־שָׁלַח מֹשֶׁה לָתוּר אֶת־הָאָרֶץ וַיִּקְרָא מֹשֶׁה לְהוֹשֵׁעַ בִּן־נוּן יְהוֹשֻׁעַ׃
וַיִּשְׁלַח אֹתָם מֹשֶׁה לָתוּר אֶת־אֶרֶץ כְּנָעַן וַיֹּאמֶר אֲלֵהֶם עֲלוּ זֶה בַּנֶּגֶב וַעֲלִיתֶם אֶת־הָהָר׃
וּרְאִיתֶם אֶת־הָאָרֶץ מַה־הִוא וְאֶת־הָעָם הַיֹּשֵׁב עָלֶיהָ הֶחָזָק הוּא הֲרָפֶה הַמְעַט הוּא אִם־רָב׃
וּמָה הָאָרֶץ אֲשֶׁר־הוּא יֹשֵׁב בָּהּ הֲטוֹבָה הִוא אִם־רָעָה וּמָה הֶעָרִים אֲשֶׁר־הוּא יוֹשֵׁב בָּהֵנָּה הַבְּמַחֲנִים אִם בְּמִבְצָרִים׃
וּמָה הָאָרֶץ הַשְּׁמֵנָה הִוא אִם־רָזָה הֲיֵשׁ־בָּהּ עֵץ אִם־אַיִן וְהִתְחַזַּקְתֶּם וּלְקַחְתֶּם מִפְּרִי הָאָרֶץ וְהַיָּמִים יְמֵי בִּכּוּרֵי עֲנָבִים׃
וַיַּעֲלוּ וַיָּתֻרוּ אֶת־הָאָרֶץ מִמִּדְבַּר־צִן עַד־רְחֹב לְבֹא חֲמָת׃
וַיַּעֲלוּ בַנֶּגֶב וַיָּבֹא עַד־חֶבְרוֹן וְשָׁם אֲחִימַן שֵׁשַׁי וְתַלְמַי יְלִידֵי הָעֲנָק וְחֶבְרוֹן שֶׁבַע שָׁנִים נִבְנְתָה לִפְנֵי צֹעַן מִצְרָיִם׃
וַיָּבֹאוּ עַד־נַחַל אֶשְׁכֹּל וַיִּכְרְתוּ מִשָּׁם זְמוֹרָה וְאֶשְׁכּוֹל עֲנָבִים אֶחָד וַיִּשָּׂאֻהוּ בַמּוֹט בִּשְׁנָיִם וּמִן־הָרִמֹּנִים וּמִן־הַתְּאֵנִים׃
לַמָּקוֹם הַהוּא קָרָא נַחַל אֶשְׁכּוֹל עַל אֹדוֹת הָאֶשְׁכּוֹל אֲשֶׁר־כָּרְתוּ מִשָּׁם בְּנֵי יִשְׂרָאֵל׃
וַיָּשֻׁבוּ מִתּוּר הָאָרֶץ מִקֵּץ אַרְבָּעִים יוֹם׃
וַיֵּלְכוּ וַיָּבֹאוּ אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן וְאֶל־כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל אֶל־מִדְבַּר פָּארָן קָדֵשָׁה וַיָּשִׁיבוּ אוֹתָם דָּבָר וְאֶת־כָּל־הָעֵדָה וַיַּרְאוּם אֶת־פְּרִי הָאָרֶץ׃
וַיְסַפְּרוּ־לוֹ וַיֹּאמְרוּ בָּאנוּ אֶל־הָאָרֶץ אֲשֶׁר שְׁלַחְתָּנוּ וְגַם זָבַת חָלָב וּדְבַשׁ הִוא וְזֶה־פִּרְיָהּ׃
אֶפֶס כִּי־עַז הָעָם הַיֹּשֵׁב בָּאָרֶץ וְהֶעָרִים בְּצֻרוֹת גְּדֹלֹת מְאֹד וְגַם־יְלִדֵי הָעֲנָק רָאִינוּ שָׁם׃
עֲמָלֵק יוֹשֵׁב בְּאֶרֶץ הַנֶּגֶב וְהַחִתִּי וְהַיְבוּסִי וְהָאֱמֹרִי יוֹשֵׁב בָּהָר וְהַכְּנַעֲנִי יֹשֵׁב עַל־הַיָּם וְעַל יַד הַיַּרְדֵּן׃
וַיַּהַס כָּלֵב אֶת־הָעָם אֶל־מֹשֶׁה וַיֹּאמֶר עָלֹה נַעֲלֶה וְיָרַשְׁנוּ אֹתָהּ כִּי־יָכוֹל נוּכַל לָהּ׃
וְהָאֲנָשִׁים אֲשֶׁר־עָלוּ עִמּוֹ אָמְרוּ לֹא נוּכַל לַעֲלוֹת אֶל־הָעָם כִּי־חָזָק הוּא מִמֶּנּוּ׃
וַיּוֹצִיאוּ דִּבַּת הָאָרֶץ אֲשֶׁר תָּרוּ אֹתָהּ אֶל־בְּנֵי יִשְׂרָאֵל לֵאמֹר הָאָרֶץ אֲשֶׁר עָבַרְנוּ בָהּ לָתוּר אֹתָהּ אֶרֶץ אֹכֶלֶת יוֹשְׁבֶיהָ הִוא וְכָל־הָעָם אֲשֶׁר־רָאִינוּ בְתוֹכָהּ אַנְשֵׁי מִדּוֹת׃
וְשָׁם רָאִינוּ אֶת־הַנְּפִילִים בְּנֵי עֲנָק מִן־הַנְּפִלִים וַנְּהִי בְעֵינֵינוּ כַּחֲגָבִים וְכֵן הָיִינוּ בְּעֵינֵיהֶם׃

Chapter 14

וַתִּשָּׂא כָּל־הָעֵדָה וַיִּתְּנוּ אֶת־קוֹלָם וַיִּבְכּוּ הָעָם בַּלַּיְלָה הַהוּא׃
וַיִּלֹּנוּ עַל־מֹשֶׁה וְעַל־אַהֲרֹן כֹּל בְּנֵי יִשְׂרָאֵל וַיֹּאמְרוּ אֲלֵהֶם כָּל־הָעֵדָה לוּ־מַתְנוּ בְּאֶרֶץ מִצְרַיִם אוֹ בַּמִּדְבָּר הַזֶּה לוּ־מָתְנוּ׃
וְלָמָה יְהוָה מֵבִיא אֹתָנוּ אֶל־הָאָרֶץ הַזֹּאת לִנְפֹּל בַּחֶרֶב נָשֵׁינוּ וְטַפֵּנוּ יִהְיוּ לָבַז הֲלוֹא טוֹב לָנוּ שׁוּב מִצְרָיְמָה׃
וַיֹּאמְרוּ אִישׁ אֶל־אָחִיו נִתְּנָה רֹאשׁ וְנָשׁוּבָה מִצְרָיְמָה׃
וַיִּפֹּל מֹשֶׁה וְאַהֲרֹן עַל־פְּנֵיהֶם לִפְנֵי כָּל־קְהַל עֲדַת בְּנֵי יִשְׂרָאֵל׃
וִיהוֹשֻׁעַ בִּן־נוּן וְכָלֵב בֶּן־יְפֻנֶּה מִן־הַתָּרִים אֶת־הָאָרֶץ קָרְעוּ בִּגְדֵיהֶם׃
וַיֹּאמְרוּ אֶל־כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל לֵאמֹר הָאָרֶץ אֲשֶׁר עָבַרְנוּ בָהּ לָתוּר אֹתָהּ טוֹבָה הָאָרֶץ מְאֹד מְאֹד׃
אִם־חָפֵץ בָּנוּ יְהוָה וְהֵבִיא אֹתָנוּ אֶל־הָאָרֶץ הַזֹּאת וּנְתָנָהּ לָנוּ אֶרֶץ אֲשֶׁר־הִוא זָבַת חָלָב וּדְבָשׁ׃
אַךְ בַּיהוָה אַל־תִּמְרֹדוּ וְאַתֶּם אַל־תִּירְאוּ אֶת־עַם הָאָרֶץ כִּי לַחְמֵנוּ הֵם סָר צִלָּם מֵעֲלֵיהֶם וַיהוָה אִתָּנוּ אַל־תִּירָאֻם׃
וַיֹּאמְרוּ כָּל־הָעֵדָה לִרְגּוֹם אֹתָם בָּאֲבָנִים וּכְבוֹד יְהוָה נִרְאָה בְּאֹהֶל מוֹעֵד אֶל־כָּל־בְּנֵי יִשְׂרָאֵל׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עַד־אָנָה יְנַאֲצֻנִי הָעָם הַזֶּה וְעַד־אָנָה לֹא־יַאֲמִינוּ בִי בְּכֹל הָאֹתוֹת אֲשֶׁר עָשִׂיתִי בְּקִרְבּוֹ׃
אַכֶּנּוּ בַדֶּבֶר וְאוֹרִשֶׁנּוּ וְאֶעֱשֶׂה אֹתְךָ לְגוֹי־גָּדוֹל וְעָצוּם מִמֶּנּוּ׃
וַיֹּאמֶר מֹשֶׁה אֶל־יְהוָה וְשָׁמְעוּ מִצְרַיִם כִּי־הֶעֱלִיתָ בְכֹחֲךָ אֶת־הָעָם הַזֶּה מִקִּרְבּוֹ׃
וְאָמְרוּ אֶל־יוֹשֵׁב הָאָרֶץ הַזֹּאת שָׁמְעוּ כִּי־אַתָּה יְהוָה בְּקֶרֶב הָעָם הַזֶּה אֲשֶׁר־עַיִן בְּעַיִן נִרְאָה אַתָּה יְהוָה וַעֲנָנְךָ עֹמֵד עֲלֵהֶם וּבְעַמֻּד עָנָן אַתָּה הֹלֵךְ לִפְנֵיהֶם יוֹמָם וּבְעַמּוּד אֵשׁ לָיְלָה׃
וְהֵמַתָּה אֶת־הָעָם הַזֶּה כְּאִישׁ אֶחָד וְאָמְרוּ הַגּוֹיִם אֲשֶׁר־שָׁמְעוּ אֶת־שִׁמְעֲךָ לֵאמֹר׃
מִבִּלְתִּי יְכֹלֶת יְהוָה לְהָבִיא אֶת־הָעָם הַזֶּה אֶל־הָאָרֶץ אֲשֶׁר־נִשְׁבַּע לָהֶם וַיִּשְׁחָטֵם בַּמִּדְבָּר׃
וְעַתָּה יִגְדַּל־נָא כֹּחַ אֲדֹנָי כַּאֲשֶׁר דִּבַּרְתָּ לֵאמֹר׃
יְהוָה אֶרֶךְ אַפַּיִם וְרַב־חֶסֶד נֹשֵׂא עָוֺן וָפָשַׁע וְנַקֵּה לֹא יְנַקֶּה פֹּקֵד עֲוֺן אָבוֹת עַל־בָּנִים עַל־שִׁלֵּשִׁים וְעַל־רִבֵּעִים׃
סְלַח־נָא לַעֲוֺן הָעָם הַזֶּה כְּגֹדֶל חַסְדֶּךָ וְכַאֲשֶׁר נָשָׂאתָה לָעָם הַזֶּה מִמִּצְרַיִם וְעַד־הֵנָּה׃
וַיֹּאמֶר יְהוָה סָלַחְתִּי כִּדְבָרֶךָ׃
וְאוּלָם חַי־אָנִי וְיִמָּלֵא כְבוֹד־יְהוָה אֶת־כָּל־הָאָרֶץ׃
כִּי כָל־הָאֲנָשִׁים הָרֹאִים אֶת־כְּבֹדִי וְאֶת־אֹתֹתַי אֲשֶׁר־עָשִׂיתִי בְמִצְרַיִם וּבַמִּדְבָּר וַיְנַסּוּ אֹתִי זֶה עֶשֶׂר פְּעָמִים וְלֹא שָׁמְעוּ בְּקוֹלִי׃
אִם־יִרְאוּ אֶת־הָאָרֶץ אֲשֶׁר נִשְׁבַּעְתִּי לַאֲבֹתָם וְכָל־מְנַאֲצַי לֹא יִרְאוּהָ׃
וְעַבְדִּי כָלֵב עֵקֶב הָיְתָה רוּחַ אַחֶרֶת עִמּוֹ וַיְמַלֵּא אַחֲרָי וַהֲבִיאֹתִיו אֶל־הָאָרֶץ אֲשֶׁר־בָּא שָׁמָּה וְזַרְעוֹ יוֹרִשֶׁנָּה׃
וְהָעֲמָלֵקִי וְהַכְּנַעֲנִי יוֹשֵׁב בָּעֵמֶק מָחָר פְּנוּ וּסְעוּ לָכֶם הַמִּדְבָּר דֶּרֶךְ יַם־סוּף׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
עַד־מָתַי לָעֵדָה הָרָעָה הַזֹּאת אֲשֶׁר הֵמָּה מַלִּינִים עָלָי אֶת־תְּלֻנּוֹת בְּנֵי יִשְׂרָאֵל אֲשֶׁר הֵמָּה מַלִּינִים עָלַי שָׁמָעְתִּי׃
אֱמֹר אֲלֵהֶם חַי־אָנִי נְאֻם־יְהוָה אִם־לֹא כַּאֲשֶׁר דִּבַּרְתֶּם בְּאָזְנָי כֵּן אֶעֱשֶׂה לָכֶם׃
בַּמִּדְבָּר הַזֶּה יִפְּלוּ פִגְרֵיכֶם וְכָל־פְּקֻדֵיכֶם לְכָל־מִסְפַּרְכֶם מִבֶּן עֶשְׂרִים שָׁנָה וָמָעְלָה אֲשֶׁר הֲלִינֹתֶם עָלָי׃
אִם־אַתֶּם תָּבֹאוּ אֶל־הָאָרֶץ אֲשֶׁר נָשָׂאתִי אֶת־יָדִי לְשַׁכֵּן אֶתְכֶם בָּהּ כִּי אִם־כָּלֵב בֶּן־יְפֻנֶּה וִיהוֹשֻׁעַ בִּן־נוּן׃
וְטַפְּכֶם אֲשֶׁר אֲמַרְתֶּם לָבַז יִהְיֶה וְהֵבֵיאתִי אֹתָם וְיָדְעוּ אֶת־הָאָרֶץ אֲשֶׁר מְאַסְתֶּם בָּהּ׃
וּפִגְרֵיכֶם אַתֶּם יִפְּלוּ בַּמִּדְבָּר הַזֶּה׃
וּבְנֵיכֶם יִהְיוּ רֹעִים בַּמִּדְבָּר אַרְבָּעִים שָׁנָה וְנָשְׂאוּ אֶת־זְנוּתֵיכֶם עַד־תֹּם פִּגְרֵיכֶם בַּמִּדְבָּר׃
בְּמִסְפַּר הַיָּמִים אֲשֶׁר־תַּרְתֶּם אֶת־הָאָרֶץ אַרְבָּעִים יוֹם יוֹם לַשָּׁנָה יוֹם לַשָּׁנָה תִּשְׂאוּ אֶת־עֲוֺנֹתֵיכֶם אַרְבָּעִים שָׁנָה וִידַעְתֶּם אֶת־תְּנוּאָתִי׃
אֲנִי יְהוָה דִּבַּרְתִּי אִם־לֹא זֹאת אֶעֱשֶׂה לְכָל־הָעֵדָה הָרָעָה הַזֹּאת הַנּוֹעָדִים עָלָי בַּמִּדְבָּר הַזֶּה יִתַּמּוּ וְשָׁם יָמֻתוּ׃
וְהָאֲנָשִׁים אֲשֶׁר־שָׁלַח מֹשֶׁה לָתוּר אֶת־הָאָרֶץ וַיָּשֻׁבוּ וילונו [וַיַּלִּינוּ] עָלָיו אֶת־כָּל־הָעֵדָה לְהוֹצִיא דִבָּה עַל־הָאָרֶץ׃
וַיָּמֻתוּ הָאֲנָשִׁים מוֹצִאֵי דִבַּת־הָאָרֶץ רָעָה בַּמַּגֵּפָה לִפְנֵי יְהוָה׃
וִיהוֹשֻׁעַ בִּן־נוּן וְכָלֵב בֶּן־יְפֻנֶּה חָיוּ מִן־הָאֲנָשִׁים הָהֵם הַהֹלְכִים לָתוּר אֶת־הָאָרֶץ׃
וַיְדַבֵּר מֹשֶׁה אֶת־הַדְּבָרִים הָאֵלֶּה אֶל־כָּל־בְּנֵי יִשְׂרָאֵל וַיִּתְאַבְּלוּ הָעָם מְאֹד׃
וַיַּשְׁכִּמוּ בַבֹּקֶר וַיַּעֲלוּ אֶל־רֹאשׁ־הָהָר לֵאמֹר הִנֶּנּוּ וְעָלִינוּ אֶל־הַמָּקוֹם אֲשֶׁר־אָמַר יְהוָה כִּי חָטָאנוּ׃
וַיֹּאמֶר מֹשֶׁה לָמָּה זֶּה אַתֶּם עֹבְרִים אֶת־פִּי יְהוָה וְהִוא לֹא תִצְלָח׃
אַל־תַּעֲלוּ כִּי אֵין יְהוָה בְּקִרְבְּכֶם וְלֹא תִּנָּגְפוּ לִפְנֵי אֹיְבֵיכֶם׃
כִּי הָעֲמָלֵקִי וְהַכְּנַעֲנִי שָׁם לִפְנֵיכֶם וּנְפַלְתֶּם בֶּחָרֶב כִּי־עַל־כֵּן שַׁבְתֶּם מֵאַחֲרֵי יְהוָה וְלֹא־יִהְיֶה יְהוָה עִמָּכֶם׃
וַיַּעְפִּלוּ לַעֲלוֹת אֶל־רֹאשׁ הָהָר וַאֲרוֹן בְּרִית־יְהוָה וּמֹשֶׁה לֹא־מָשׁוּ מִקֶּרֶב הַמַּחֲנֶה׃
וַיֵּרֶד הָעֲמָלֵקִי וְהַכְּנַעֲנִי הַיֹּשֵׁב בָּהָר הַהוּא וַיַּכּוּם וַיַּכְּתוּם עַד־הַחָרְמָה׃

Chapter 15

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם כִּי תָבֹאוּ אֶל־אֶרֶץ מוֹשְׁבֹתֵיכֶם אֲשֶׁר אֲנִי נֹתֵן לָכֶם׃
וַעֲשִׂיתֶם אִשֶּׁה לַיהוָה עֹלָה אוֹ־זֶבַח לְפַלֵּא־נֶדֶר אוֹ בִנְדָבָה אוֹ בְּמֹעֲדֵיכֶם לַעֲשׂוֹת רֵיחַ נִיחֹחַ לַיהוָה מִן־הַבָּקָר אוֹ מִן־הַצֹּאן׃
וְהִקְרִיב הַמַּקְרִיב קָרְבָּנוֹ לַיהוָה מִנְחָה סֹלֶת עִשָּׂרוֹן בָּלוּל בִּרְבִעִית הַהִין שָׁמֶן׃
וְיַיִן לַנֶּסֶךְ רְבִיעִית הַהִין תַּעֲשֶׂה עַל־הָעֹלָה אוֹ לַזָּבַח לַכֶּבֶשׂ הָאֶחָד׃
אוֹ לָאַיִל תַּעֲשֶׂה מִנְחָה סֹלֶת שְׁנֵי עֶשְׂרֹנִים בְּלוּלָה בַשֶּׁמֶן שְׁלִשִׁית הַהִין׃
וְיַיִן לַנֶּסֶךְ שְׁלִשִׁית הַהִין תַּקְרִיב רֵיחַ־נִיחֹחַ לַיהוָה׃
וְכִי־תַעֲשֶׂה בֶן־בָּקָר עֹלָה אוֹ־זָבַח לְפַלֵּא־נֶדֶר אוֹ־שְׁלָמִים לַיהוָה׃
וְהִקְרִיב עַל־בֶּן־הַבָּקָר מִנְחָה סֹלֶת שְׁלֹשָׁה עֶשְׂרֹנִים בָּלוּל בַּשֶּׁמֶן חֲצִי הַהִין׃
וְיַיִן תַּקְרִיב לַנֶּסֶךְ חֲצִי הַהִין אִשֵּׁה רֵיחַ־נִיחֹחַ לַיהוָה׃
כָּכָה יֵעָשֶׂה לַשּׁוֹר הָאֶחָד אוֹ לָאַיִל הָאֶחָד אוֹ־לַשֶּׂה בַכְּבָשִׂים אוֹ בָעִזִּים׃
כַּמִּסְפָּר אֲשֶׁר תַּעֲשׂוּ כָּכָה תַּעֲשׂוּ לָאֶחָד כְּמִסְפָּרָם׃
כָּל־הָאֶזְרָח יַעֲשֶׂה־כָּכָה אֶת־אֵלֶּה לְהַקְרִיב אִשֵּׁה רֵיחַ־נִיחֹחַ לַיהוָה׃
וְכִי־יָגוּר אִתְּכֶם גֵּר אוֹ אֲשֶׁר־בְּתוֹכְכֶם לְדֹרֹתֵיכֶם וְעָשָׂה אִשֵּׁה רֵיחַ־נִיחֹחַ לַיהוָה כַּאֲשֶׁר תַּעֲשׂוּ כֵּן יַעֲשֶׂה׃
הַקָּהָל חֻקָּה אַחַת לָכֶם וְלַגֵּר הַגָּר חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם כָּכֶם כַּגֵּר יִהְיֶה לִפְנֵי יְהוָה׃
תּוֹרָה אַחַת וּמִשְׁפָּט אֶחָד יִהְיֶה לָכֶם וְלַגֵּר הַגָּר אִתְּכֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם בְּבֹאֲכֶם אֶל־הָאָרֶץ אֲשֶׁר אֲנִי מֵבִיא אֶתְכֶם שָׁמָּה׃
וְהָיָה בַּאֲכָלְכֶם מִלֶּחֶם הָאָרֶץ תָּרִימוּ תְרוּמָה לַיהוָה׃
רֵאשִׁית עֲרִסֹתֵכֶם חַלָּה תָּרִימוּ תְרוּמָה כִּתְרוּמַת גֹּרֶן כֵּן תָּרִימוּ אֹתָהּ׃
מֵרֵאשִׁית עֲרִסֹתֵיכֶם תִּתְּנוּ לַיהוָה תְּרוּמָה לְדֹרֹתֵיכֶם׃
וְכִי תִשְׁגּוּ וְלֹא תַעֲשׂוּ אֵת כָּל־הַמִּצְוֺת הָאֵלֶּה אֲשֶׁר־דִּבֶּר יְהוָה אֶל־מֹשֶׁה׃
אֵת כָּל־אֲשֶׁר צִוָּה יְהוָה אֲלֵיכֶם בְּיַד־מֹשֶׁה מִן־הַיּוֹם אֲשֶׁר צִוָּה יְהוָה וָהָלְאָה לְדֹרֹתֵיכֶם׃
וְהָיָה אִם מֵעֵינֵי הָעֵדָה נֶעֶשְׂתָה לִשְׁגָגָה וְעָשׂוּ כָל־הָעֵדָה פַּר בֶּן־בָּקָר אֶחָד לְעֹלָה לְרֵיחַ נִיחֹחַ לַיהוָה וּמִנְחָתוֹ וְנִסְכּוֹ כַּמִּשְׁפָּט וּשְׂעִיר־עִזִּים אֶחָד לְחַטָּת׃
וְכִפֶּר הַכֹּהֵן עַל־כָּל־עֲדַת בְּנֵי יִשְׂרָאֵל וְנִסְלַח לָהֶם כִּי־שְׁגָגָה הִוא וְהֵם הֵבִיאוּ אֶת־קָרְבָּנָם אִשֶּׁה לַיהוָה וְחַטָּאתָם לִפְנֵי יְהוָה עַל־שִׁגְגָתָם׃
וְנִסְלַח לְכָל־עֲדַת בְּנֵי יִשְׂרָאֵל וְלַגֵּר הַגָּר בְּתוֹכָם כִּי לְכָל־הָעָם בִּשְׁגָגָה׃
וְאִם־נֶפֶשׁ אַחַת תֶּחֱטָא בִשְׁגָגָה וְהִקְרִיבָה עֵז בַּת־שְׁנָתָהּ לְחַטָּאת׃
וְכִפֶּר הַכֹּהֵן עַל־הַנֶּפֶשׁ הַשֹּׁגֶגֶת בְּחֶטְאָה בִשְׁגָגָה לִפְנֵי יְהוָה לְכַפֵּר עָלָיו וְנִסְלַח לוֹ׃
הָאֶזְרָח בִּבְנֵי יִשְׂרָאֵל וְלַגֵּר הַגָּר בְּתוֹכָם תּוֹרָה אַחַת יִהְיֶה לָכֶם לָעֹשֶׂה בִּשְׁגָגָה׃
וְהַנֶּפֶשׁ אֲשֶׁר־תַּעֲשֶׂה בְּיָד רָמָה מִן־הָאֶזְרָח וּמִן־הַגֵּר אֶת־יְהוָה הוּא מְגַדֵּף וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מִקֶּרֶב עַמָּהּ׃
כִּי דְבַר־יְהוָה בָּזָה וְאֶת־מִצְוָתוֹ הֵפַר הִכָּרֵת תִּכָּרֵת הַנֶּפֶשׁ הַהִוא עֲוֺנָה בָהּ׃
וַיִּהְיוּ בְנֵי־יִשְׂרָאֵל בַּמִּדְבָּר וַיִּמְצְאוּ אִישׁ מְקֹשֵׁשׁ עֵצִים בְּיוֹם הַשַּׁבָּת׃
וַיַּקְרִיבוּ אֹתוֹ הַמֹּצְאִים אֹתוֹ מְקֹשֵׁשׁ עֵצִים אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן וְאֶל כָּל־הָעֵדָה׃
וַיַּנִּיחוּ אֹתוֹ בַּמִּשְׁמָר כִּי לֹא פֹרַשׁ מַה־יֵּעָשֶׂה לוֹ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה מוֹת יוּמַת הָאִישׁ רָגוֹם אֹתוֹ בָאֲבָנִים כָּל־הָעֵדָה מִחוּץ לַמַּחֲנֶה׃
וַיֹּצִיאוּ אֹתוֹ כָּל־הָעֵדָה אֶל־מִחוּץ לַמַּחֲנֶה וַיִּרְגְּמוּ אֹתוֹ בָּאֲבָנִים וַיָּמֹת כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם וְעָשׂוּ לָהֶם צִיצִת עַל־כַּנְפֵי בִגְדֵיהֶם לְדֹרֹתָם וְנָתְנוּ עַל־צִיצִת הַכָּנָף פְּתִיל תְּכֵלֶת׃
וְהָיָה לָכֶם לְצִיצִת וּרְאִיתֶם אֹתוֹ וּזְכַרְתֶּם אֶת־כָּל־מִצְוֺת יְהוָה וַעֲשִׂיתֶם אֹתָם וְלֹא־תָתֻרוּ אַחֲרֵי לְבַבְכֶם וְאַחֲרֵי עֵינֵיכֶם אֲשֶׁר־אַתֶּם זֹנִים אַחֲרֵיהֶם׃
לְמַעַן תִּזְכְּרוּ וַעֲשִׂיתֶם אֶת־כָּל־מִצְוֺתָי וִהְיִיתֶם קְדֹשִׁים לֵאלֹהֵיכֶם׃
אֲנִי יְהוָה אֱלֹהֵיכֶם אֲשֶׁר הוֹצֵאתִי אֶתְכֶם מֵאֶרֶץ מִצְרַיִם לִהְיוֹת לָכֶם לֵאלֹהִים אֲנִי יְהוָה אֱלֹהֵיכֶם׃

Chapter 16

וַיִּקַּח קֹרַח בֶּן־יִצְהָר בֶּן־קְהָת בֶּן־לֵוִי וְדָתָן וַאֲבִירָם בְּנֵי אֱלִיאָב וְאוֹן בֶּן־פֶּלֶת בְּנֵי רְאוּבֵן׃
וַיָּקֻמוּ לִפְנֵי מֹשֶׁה וַאֲנָשִׁים מִבְּנֵי־יִשְׂרָאֵל חֲמִשִּׁים וּמָאתָיִם נְשִׂיאֵי עֵדָה קְרִאֵי מוֹעֵד אַנְשֵׁי־שֵׁם׃
וַיִּקָּהֲלוּ עַל־מֹשֶׁה וְעַל־אַהֲרֹן וַיֹּאמְרוּ אֲלֵהֶם רַב־לָכֶם כִּי כָל־הָעֵדָה כֻּלָּם קְדֹשִׁים וּבְתוֹכָם יְהוָה וּמַדּוּעַ תִּתְנַשְּׂאוּ עַל־קְהַל יְהוָה׃
וַיִּשְׁמַע מֹשֶׁה וַיִּפֹּל עַל־פָּנָיו׃
וַיְדַבֵּר אֶל־קֹרַח וְאֶל־כָּל־עֲדָתוֹ לֵאמֹר בֹּקֶר וְיֹדַע יְהוָה אֶת־אֲשֶׁר־לוֹ וְאֶת־הַקָּדוֹשׁ וְהִקְרִיב אֵלָיו וְאֵת אֲשֶׁר יִבְחַר־בּוֹ יַקְרִיב אֵלָיו׃
זֹאת עֲשׂוּ קְחוּ־לָכֶם מַחְתּוֹת קֹרַח וְכָל־עֲדָתוֹ׃
וּתְנוּ בָהֵן אֵשׁ וְשִׂימוּ עֲלֵיהֶן קְטֹרֶת לִפְנֵי יְהוָה מָחָר וְהָיָה הָאִישׁ אֲשֶׁר־יִבְחַר יְהוָה הוּא הַקָּדוֹשׁ רַב־לָכֶם בְּנֵי לֵוִי׃
וַיֹּאמֶר מֹשֶׁה אֶל־קֹרַח שִׁמְעוּ־נָא בְּנֵי לֵוִי׃
הַמְעַט מִכֶּם כִּי־הִבְדִּיל אֱלֹהֵי יִשְׂרָאֵל אֶתְכֶם מֵעֲדַת יִשְׂרָאֵל לְהַקְרִיב אֶתְכֶם אֵלָיו לַעֲבֹד אֶת־עֲבֹדַת מִשְׁכַּן יְהוָה וְלַעֲמֹד לִפְנֵי הָעֵדָה לְשָׁרְתָם׃
וַיַּקְרֵב אֹתְךָ וְאֶת־כָּל־אַחֶיךָ בְנֵי־לֵוִי אִתָּךְ וּבִקַּשְׁתֶּם גַּם־כְּהֻנָּה׃
לָכֵן אַתָּה וְכָל־עֲדָתְךָ הַנֹּעָדִים עַל־יְהוָה וְאַהֲרֹן מַה־הוּא כִּי תלונו [תַלִּינוּ] עָלָיו׃
וַיִּשְׁלַח מֹשֶׁה לִקְרֹא לְדָתָן וְלַאֲבִירָם בְּנֵי אֱלִיאָב וַיֹּאמְרוּ לֹא נַעֲלֶה׃
הַמְעַט כִּי הֶעֱלִיתָנוּ מֵאֶרֶץ זָבַת חָלָב וּדְבַשׁ לַהֲמִיתֵנוּ בַּמִּדְבָּר כִּי־תִשְׂתָּרֵר עָלֵינוּ גַּם־הִשְׂתָּרֵר׃
אַף לֹא אֶל־אֶרֶץ זָבַת חָלָב וּדְבַשׁ הֲבִיאֹתָנוּ וַתִּתֶּן־לָנוּ נַחֲלַת שָׂדֶה וָכָרֶם הַעֵינֵי הָאֲנָשִׁים הָהֵם תְּנַקֵּר לֹא נַעֲלֶה׃
וַיִּחַר לְמֹשֶׁה מְאֹד וַיֹּאמֶר אֶל־יְהוָה אַל־תֵּפֶן אֶל־מִנְחָתָם לֹא חֲמוֹר אֶחָד מֵהֶם נָשָׂאתִי וְלֹא הֲרֵעֹתִי אֶת־אַחַד מֵהֶם׃
וַיֹּאמֶר מֹשֶׁה אֶל־קֹרַח אַתָּה וְכָל־עֲדָתְךָ הֱיוּ לִפְנֵי יְהוָה אַתָּה וָהֵם וְאַהֲרֹן מָחָר׃
וּקְחוּ אִישׁ מַחְתָּתוֹ וּנְתַתֶּם עֲלֵיהֶם קְטֹרֶת וְהִקְרַבְתֶּם לִפְנֵי יְהוָה אִישׁ מַחְתָּתוֹ חֲמִשִּׁים וּמָאתַיִם מַחְתֹּת וְאַתָּה וְאַהֲרֹן אִישׁ מַחְתָּתוֹ׃
וַיִּקְחוּ אִישׁ מַחְתָּתוֹ וַיִּתְּנוּ עֲלֵיהֶם אֵשׁ וַיָּשִׂימוּ עֲלֵיהֶם קְטֹרֶת וַיַּעַמְדוּ פֶּתַח אֹהֶל מוֹעֵד וּמֹשֶׁה וְאַהֲרֹן׃
וַיַּקְהֵל עֲלֵיהֶם קֹרַח אֶת־כָּל־הָעֵדָה אֶל־פֶּתַח אֹהֶל מוֹעֵד וַיֵּרָא כְבוֹד־יְהוָה אֶל־כָּל־הָעֵדָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
הִבָּדְלוּ מִתּוֹךְ הָעֵדָה הַזֹּאת וַאַכַלֶּה אֹתָם כְּרָגַע׃
וַיִּפְּלוּ עַל־פְּנֵיהֶם וַיֹּאמְרוּ אֵל אֱלֹהֵי הָרוּחֹת לְכָל־בָּשָׂר הָאִישׁ אֶחָד יֶחֱטָא וְעַל כָּל־הָעֵדָה תִּקְצֹף׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־הָעֵדָה לֵאמֹר הֵעָלוּ מִסָּבִיב לְמִשְׁכַּן־קֹרַח דָּתָן וַאֲבִירָם׃
וַיָּקָם מֹשֶׁה וַיֵּלֶךְ אֶל־דָּתָן וַאֲבִירָם וַיֵּלְכוּ אַחֲרָיו זִקְנֵי יִשְׂרָאֵל׃
וַיְדַבֵּר אֶל־הָעֵדָה לֵאמֹר סוּרוּ נָא מֵעַל אָהֳלֵי הָאֲנָשִׁים הָרְשָׁעִים הָאֵלֶּה וְאַל־תִּגְּעוּ בְּכָל־אֲשֶׁר לָהֶם פֶּן־תִּסָּפוּ בְּכָל־חַטֹּאתָם׃
וַיֵּעָלוּ מֵעַל מִשְׁכַּן־קֹרֶח דָּתָן וַאֲבִירָם מִסָּבִיב וְדָתָן וַאֲבִירָם יָצְאוּ נִצָּבִים פֶּתַח אָהֳלֵיהֶם וּנְשֵׁיהֶם וּבְנֵיהֶם וְטַפָּם׃
וַיֹּאמֶר מֹשֶׁה בְּזֹאת תֵּדְעוּן כִּי־יְהוָה שְׁלָחַנִי לַעֲשׂוֹת אֵת כָּל־הַמַּעֲשִׂים הָאֵלֶּה כִּי־לֹא מִלִּבִּי׃
אִם־כְּמוֹת כָּל־הָאָדָם יְמֻתוּן אֵלֶּה וּפְקֻדַּת כָּל־הָאָדָם יִפָּקֵד עֲלֵיהֶם לֹא יְהוָה שְׁלָחָנִי׃
וְאִם־בְּרִיאָה יִבְרָא יְהוָה וּפָצְתָה הָאֲדָמָה אֶת־פִּיהָ וּבָלְעָה אֹתָם וְאֶת־כָּל־אֲשֶׁר לָהֶם וְיָרְדוּ חַיִּים שְׁאֹלָה וִידַעְתֶּם כִּי נִאֲצוּ הָאֲנָשִׁים הָאֵלֶּה אֶת־יְהוָה׃
וַיְהִי כְּכַלֹּתוֹ לְדַבֵּר אֵת כָּל־הַדְּבָרִים הָאֵלֶּה וַתִּבָּקַע הָאֲדָמָה אֲשֶׁר תַּחְתֵּיהֶם׃
וַתִּפְתַּח הָאָרֶץ אֶת־פִּיהָ וַתִּבְלַע אֹתָם וְאֶת־בָּתֵּיהֶם וְאֵת כָּל־הָאָדָם אֲשֶׁר לְקֹרַח וְאֵת כָּל־הָרֲכוּשׁ׃
וַיֵּרְדוּ הֵם וְכָל־אֲשֶׁר לָהֶם חַיִּים שְׁאֹלָה וַתְּכַס עֲלֵיהֶם הָאָרֶץ וַיֹּאבְדוּ מִתּוֹךְ הַקָּהָל׃
וְכָל־יִשְׂרָאֵל אֲשֶׁר סְבִיבֹתֵיהֶם נָסוּ לְקֹלָם כִּי אָמְרוּ פֶּן־תִּבְלָעֵנוּ הָאָרֶץ׃
וְאֵשׁ יָצְאָה מֵאֵת יְהוָה וַתֹּאכַל אֵת הַחֲמִשִּׁים וּמָאתַיִם אִישׁ מַקְרִיבֵי הַקְּטֹרֶת׃

Chapter 17

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
אֱמֹר אֶל־אֶלְעָזָר בֶּן־אַהֲרֹן הַכֹּהֵן וְיָרֵם אֶת־הַמַּחְתֹּת מִבֵּין הַשְּׂרֵפָה וְאֶת־הָאֵשׁ זְרֵה־הָלְאָה כִּי קָדֵשׁוּ׃
אֵת מַחְתּוֹת הַחַטָּאִים הָאֵלֶּה בְּנַפְשֹׁתָם וְעָשׂוּ אֹתָם רִקֻּעֵי פַחִים צִפּוּי לַמִּזְבֵּחַ כִּי־הִקְרִיבֻם לִפְנֵי־יְהוָה וַיִּקְדָּשׁוּ וְיִהְיוּ לְאוֹת לִבְנֵי יִשְׂרָאֵל׃
וַיִּקַּח אֶלְעָזָר הַכֹּהֵן אֵת מַחְתּוֹת הַנְּחֹשֶׁת אֲשֶׁר הִקְרִיבוּ הַשְּׂרֻפִים וַיְרַקְּעוּם צִפּוּי לַמִּזְבֵּחַ׃
זִכָּרוֹן לִבְנֵי יִשְׂרָאֵל לְמַעַן אֲשֶׁר לֹא־יִקְרַב אִישׁ זָר אֲשֶׁר לֹא מִזֶּרַע אַהֲרֹן הוּא לְהַקְטִיר קְטֹרֶת לִפְנֵי יְהוָה וְלֹא־יִהְיֶה כְקֹרַח וְכַעֲדָתוֹ כַּאֲשֶׁר דִּבֶּר יְהוָה בְּיַד־מֹשֶׁה לוֹ׃
וַיִּלֹּנוּ כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל מִמָּחֳרָת עַל־מֹשֶׁה וְעַל־אַהֲרֹן לֵאמֹר אַתֶּם הֲמִתֶּם אֶת־עַם יְהוָה׃
וַיְהִי בְּהִקָּהֵל הָעֵדָה עַל־מֹשֶׁה וְעַל־אַהֲרֹן וַיִּפְנוּ אֶל־אֹהֶל מוֹעֵד וְהִנֵּה כִסָּהוּ הֶעָנָן וַיֵּרָא כְּבוֹד יְהוָה׃
וַיָּבֹא מֹשֶׁה וְאַהֲרֹן אֶל־פְּנֵי אֹהֶל מוֹעֵד׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
הֵרֹמּוּ מִתּוֹךְ הָעֵדָה הַזֹּאת וַאֲכַלֶּה אֹתָם כְּרָגַע וַיִּפְּלוּ עַל־פְּנֵיהֶם׃
וַיֹּאמֶר מֹשֶׁה אֶל־אַהֲרֹן קַח אֶת־הַמַּחְתָּה וְתֶן־עָלֶיהָ אֵשׁ מֵעַל הַמִּזְבֵּחַ וְשִׂים קְטֹרֶת וְהוֹלֵךְ מְהֵרָה אֶל־הָעֵדָה וְכַפֵּר עֲלֵיהֶם כִּי־יָצָא הַקֶּצֶף מִלִּפְנֵי יְהוָה הֵחֵל הַנָּגֶף׃
וַיִּקַּח אַהֲרֹן כַּאֲשֶׁר דִּבֶּר מֹשֶׁה וַיָּרָץ אֶל־תּוֹך הַקָּהָל וְהִנֵּה הֵחֵל הַנֶּגֶף בָּעָם וַיִּתֵּן אֶת־הַקְּטֹרֶת וַיְכַפֵּר עַל־הָעָם׃
וַיַּעֲמֹד בֵּין־הַמֵּתִים וּבֵין הַחַיִּים וַתֵּעָצַר הַמַּגֵּפָה׃
וַיִּהְיוּ הַמֵּתִים בַּמַּגֵּפָה אַרְבָּעָה עָשָׂר אֶלֶף וּשְׁבַע מֵאוֹת מִלְּבַד הַמֵּתִים עַל־דְּבַר־קֹרַח׃
וַיָּשָׁב אַהֲרֹן אֶל־מֹשֶׁה אֶל־פֶּתַח אֹהֶל מוֹעֵד וְהַמַּגֵּפָה נֶעֱצָרָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְקַח מֵאִתָּם מַטֶּה מַטֶּה לְבֵית אָב מֵאֵת כָּל־נְשִׂיאֵהֶם לְבֵית אֲבֹתָם שְׁנֵים עָשָׂר מַטּוֹת אִישׁ אֶת־שְׁמוֹ תִּכְתֹּב עַל־מַטֵּהוּ׃
וְאֵת שֵׁם אַהֲרֹן תִּכְתֹּב עַל־מַטֵּה לֵוִי כִּי מַטֶּה אֶחָד לְרֹאשׁ בֵּית אֲבוֹתָם׃
וְהִנַּחְתָּם בְּאֹהֶל מוֹעֵד לִפְנֵי הָעֵדוּת אֲשֶׁר אִוָּעֵד לָכֶם שָׁמָּה׃
וְהָיָה הָאִישׁ אֲשֶׁר אֶבְחַר־בּוֹ מַטֵּהוּ יִפְרָח וַהֲשִׁכֹּתִי מֵעָלַי אֶת־תְּלֻנּוֹת בְּנֵי יִשְׂרָאֵל אֲשֶׁר הֵם מַלִּינִם עֲלֵיכֶם׃
וַיְדַבֵּר מֹשֶׁה אֶל־בְּנֵי יִשְׂרָאֵל וַיִּתְּנוּ אֵלָיו כָּל־נְשִׂיאֵיהֶם מַטֶּה לְנָשִׂיא אֶחָד מַטֶּה לְנָשִׂיא אֶחָד לְבֵית אֲבֹתָם שְׁנֵים עָשָׂר מַטּוֹת וּמַטֵּה אַהֲרֹן בְּתוֹךְ מַטּוֹתָם׃
וַיַּנַּח מֹשֶׁה אֶת־הַמַּטֹּת לִפְנֵי יְהוָה בְּאֹהֶל הָעֵדֻת׃
וַיְהִי מִמָּחֳרָת וַיָּבֹא מֹשֶׁה אֶל־אֹהֶל הָעֵדוּת וְהִנֵּה פָּרַח מַטֵּה־אַהֲרֹן לְבֵית לֵוִי וַיֹּצֵא פֶרַח וַיָּצֵץ צִיץ וַיִּגְמֹל שְׁקֵדִים׃
וַיֹּצֵא מֹשֶׁה אֶת־כָּל־הַמַּטֹּת מִלִּפְנֵי יְהוָה אֶל־כָּל־בְּנֵי יִשְׂרָאֵל וַיִּרְאוּ וַיִּקְחוּ אִישׁ מַטֵּהוּ׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה הָשֵׁב אֶת־מַטֵּה אַהֲרֹן לִפְנֵי הָעֵדוּת לְמִשְׁמֶרֶת לְאוֹת לִבְנֵי־מֶרִי וּתְכַל תְּלוּנֹּתָם מֵעָלַי וְלֹא יָמֻתוּ׃
וַיַּעַשׂ מֹשֶׁה כַּאֲשֶׁר צִוָּה יְהוָה אֹתוֹ כֵּן עָשָׂה׃
וַיֹּאמְרוּ בְּנֵי יִשְׂרָאֵל אֶל־מֹשֶׁה לֵאמֹר הֵן גָּוַעְנוּ אָבַדְנוּ כֻּלָּנוּ אָבָדְנוּ׃
כֹּל הַקָּרֵב הַקָּרֵב אֶל־מִשְׁכַּן יְהוָה יָמוּת הַאִם תַּמְנוּ לִגְוֺעַ׃

Chapter 18

וַיֹּאמֶר יְהוָה אֶל־אַהֲרֹן אַתָּה וּבָנֶיךָ וּבֵית־אָבִיךָ אִתָּךְ תִּשְׂאוּ אֶת־עֲוֺן הַמִּקְדָּשׁ וְאַתָּה וּבָנֶיךָ אִתָּךְ תִּשְׂאוּ אֶת־עֲוֺן כְּהֻנַּתְכֶם׃
וְגַם אֶת־אַחֶיךָ מַטֵּה לֵוִי שֵׁבֶט אָבִיךָ הַקְרֵב אִתָּךְ וְיִלָּווּ עָלֶיךָ וִישָׁרְתוּךָ וְאַתָּה וּבָנֶיךָ אִתָּךְ לִפְנֵי אֹהֶל הָעֵדֻת׃
וְשָׁמְרוּ מִשְׁמַרְתְּךָ וּמִשְׁמֶרֶת כָּל־הָאֹהֶל אַךְ אֶל־כְּלֵי הַקֹּדֶשׁ וְאֶל־הַמִּזְבֵּחַ לֹא יִקְרָבוּ וְלֹא־יָמֻתוּ גַם־הֵם גַּם־אַתֶּם׃
וְנִלְווּ עָלֶיךָ וְשָׁמְרוּ אֶת־מִשְׁמֶרֶת אֹהֶל מוֹעֵד לְכֹל עֲבֹדַת הָאֹהֶל וְזָר לֹא־יִקְרַב אֲלֵיכֶם׃
וּשְׁמַרְתֶּם אֵת מִשְׁמֶרֶת הַקֹּדֶשׁ וְאֵת מִשְׁמֶרֶת הַמִּזְבֵּחַ וְלֹא־יִהְיֶה עוֹד קֶצֶף עַל־בְּנֵי יִשְׂרָאֵל׃
וַאֲנִי הִנֵּה לָקַחְתִּי אֶת־אֲחֵיכֶם הַלְוִיִּם מִתּוֹךְ בְּנֵי יִשְׂרָאֵל לָכֶם מַתָּנָה נְתֻנִים לַיהוָה לַעֲבֹד אֶת־עֲבֹדַת אֹהֶל מוֹעֵד׃
וְאַתָּה וּבָנֶיךָ אִתְּךָ תִּשְׁמְרוּ אֶת־כְּהֻנַּתְכֶם לְכָל־דְּבַר הַמִּזְבֵּחַ וּלְמִבֵּית לַפָּרֹכֶת וַעֲבַדְתֶּם עֲבֹדַת מַתָּנָה אֶתֵּן אֶת־כְּהֻנַּתְכֶם וְהַזָּר הַקָּרֵב יוּמָת׃
וַיְדַבֵּר יְהוָה אֶל־אַהֲרֹן וַאֲנִי הִנֵּה נָתַתִּי לְךָ אֶת־מִשְׁמֶרֶת תְּרוּמֹתָי לְכָל־קָדְשֵׁי בְנֵי־יִשְׂרָאֵל לְךָ נְתַתִּים לְמָשְׁחָה וּלְבָנֶיךָ לְחָק־עוֹלָם׃
זֶה־יִהְיֶה לְךָ מִקֹּדֶשׁ הַקֳּדָשִׁים מִן־הָאֵשׁ כָּל־קָרְבָּנָם לְכָל־מִנְחָתָם וּלְכָל־חַטָּאתָם וּלְכָל־אֲשָׁמָם אֲשֶׁר יָשִׁיבוּ לִי קֹדֶשׁ קָדָשִׁים לְךָ הוּא וּלְבָנֶיךָ׃
בְּקֹדֶשׁ הַקֳּדָשִׁים תֹּאכֲלֶנּוּ כָּל־זָכָר יֹאכַל אֹתוֹ קֹדֶשׁ יִהְיֶה־לָּךְ׃
וְזֶה־לְּךָ תְּרוּמַת מַתָּנָם לְכָל־תְּנוּפֹת בְּנֵי יִשְׂרָאֵל לְךָ נְתַתִּים וּלְבָנֶיךָ וְלִבְנֹתֶיךָ אִתְּךָ לְחָק־עוֹלָם כָּל־טָהוֹר בְּבֵיתְךָ יֹאכַל אֹתוֹ׃
כֹּל חֵלֶב יִצְהָר וְכָל־חֵלֶב תִּירוֹשׁ וְדָגָן רֵאשִׁיתָם אֲשֶׁר־יִתְּנוּ לַיהוָה לְךָ נְתַתִּים׃
בִּכּוּרֵי כָּל־אֲשֶׁר בְּאַרְצָם אֲשֶׁר־יָבִיאוּ לַיהוָה לְךָ יִהְיֶה כָּל־טָהוֹר בְּבֵיתְךָ יֹאכֲלֶנּוּ׃
כָּל־חֵרֶם בְּיִשְׂרָאֵל לְךָ יִהְיֶה׃
כָּל־פֶּטֶר רֶחֶם לְכָל־בָּשָׂר אֲשֶׁר־יַקְרִיבוּ לַיהוָה בָּאָדָם וּבַבְּהֵמָה יִהְיֶה־לָּךְ אַךְ פָּדֹה תִפְדֶּה אֵת בְּכוֹר הָאָדָם וְאֵת בְּכוֹר־הַבְּהֵמָה הַטְּמֵאָה תִּפְדֶּה׃
וּפְדוּיָו מִבֶּן־חֹדֶשׁ תִּפְדֶּה בְּעֶרְכְּךָ כֶּסֶף חֲמֵשֶׁת שְׁקָלִים בְּשֶׁקֶל הַקֹּדֶשׁ עֶשְׂרִים גֵּרָה הוּא׃
אַךְ בְּכוֹר־שׁוֹר אוֹ־בְכוֹר כֶּשֶׂב אוֹ־בְכוֹר עֵז לֹא תִפְדֶּה קֹדֶשׁ הֵם אֶת־דָּמָם תִּזְרֹק עַל־הַמִּזְבֵּחַ וְאֶת־חֶלְבָּם תַּקְטִיר אִשֶּׁה לְרֵיחַ נִיחֹחַ לַיהוָה׃
וּבְשָׂרָם יִהְיֶה־לָּךְ כַּחֲזֵה הַתְּנוּפָה וּכְשׁוֹק הַיָּמִין לְךָ יִהְיֶה׃
כֹּל תְּרוּמֹת הַקֳּדָשִׁים אֲשֶׁר יָרִימוּ בְנֵי־יִשְׂרָאֵל לַיהוָה נָתַתִּי לְךָ וּלְבָנֶיךָ וְלִבְנֹתֶיךָ אִתְּךָ לְחָק־עוֹלָם בְּרִית מֶלַח עוֹלָם הִוא לִפְנֵי יְהוָה לְךָ וּלְזַרְעֲךָ אִתָּךְ׃
וַיֹּאמֶר יְהוָה אֶל־אַהֲרֹן בְּאַרְצָם לֹא תִנְחָל וְחֵלֶק לֹא־יִהְיֶה לְךָ בְּתוֹכָם אֲנִי חֶלְקְךָ וְנַחֲלָתְךָ בְּתוֹךְ בְּנֵי יִשְׂרָאֵל׃
וְלִבְנֵי לֵוִי הִנֵּה נָתַתִּי כָּל־מַעֲשֵׂר בְּיִשְׂרָאֵל לְנַחֲלָה חֵלֶף עֲבֹדָתָם אֲשֶׁר־הֵם עֹבְדִים אֶת־עֲבֹדַת אֹהֶל מוֹעֵד׃
וְלֹא־יִקְרְבוּ עוֹד בְּנֵי יִשְׂרָאֵל אֶל־אֹהֶל מוֹעֵד לָשֵׂאת חֵטְא לָמוּת׃
וְעָבַד הַלֵּוִי הוּא אֶת־עֲבֹדַת אֹהֶל מוֹעֵד וְהֵם יִשְׂאוּ עֲוֺנָם חֻקַּת עוֹלָם לְדֹרֹתֵיכֶם וּבְתוֹךְ בְּנֵי יִשְׂרָאֵל לֹא יִנְחֲלוּ נַחֲלָה׃
כִּי אֶת־מַעְשַׂר בְּנֵי־יִשְׂרָאֵל אֲשֶׁר יָרִימוּ לַיהוָה תְּרוּמָה נָתַתִּי לַלְוִיִּם לְנַחֲלָה עַל־כֵּן אָמַרְתִּי לָהֶם בְּתוֹךְ בְּנֵי יִשְׂרָאֵל לֹא יִנְחֲלוּ נַחֲלָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
וְאֶל־הַלְוִיִּם תְּדַבֵּר וְאָמַרְתָּ אֲלֵהֶם כִּי־תִקְחוּ מֵאֵת בְּנֵי־יִשְׂרָאֵל אֶת־הַמַּעֲשֵׂר אֲשֶׁר נָתַתִּי לָכֶם מֵאִתָּם בְּנַחֲלַתְכֶם וַהֲרֵמֹתֶם מִמֶּנּוּ תְּרוּמַת יְהוָה מַעֲשֵׂר מִן־הַמַּעֲשֵׂר׃
וְנֶחְשַׁב לָכֶם תְּרוּמַתְכֶם כַּדָּגָן מִן־הַגֹּרֶן וְכַמְלֵאָה מִן־הַיָּקֶב׃
כֵּן תָּרִימוּ גַם־אַתֶּם תְּרוּמַת יְהוָה מִכֹּל מַעְשְׂרֹתֵיכֶם אֲשֶׁר תִּקְחוּ מֵאֵת בְּנֵי יִשְׂרָאֵל וּנְתַתֶּם מִמֶּנּוּ אֶת־תְּרוּמַת יְהוָה לְאַהֲרֹן הַכֹּהֵן׃
מִכֹּל מַתְּנֹתֵיכֶם תָּרִימוּ אֵת כָּל־תְּרוּמַת יְהוָה מִכָּל־חֶלְבּוֹ אֶת־מִקְדְּשׁוֹ מִמֶּנּוּ׃
וְאָמַרְתָּ אֲלֵהֶם בַּהֲרִימְכֶם אֶת־חֶלְבּוֹ מִמֶּנּוּ וְנֶחְשַׁב לַלְוִיִּם כִּתְבוּאַת גֹּרֶן וְכִתְבוּאַת יָקֶב׃
וַאֲכַלְתֶּם אֹתוֹ בְּכָל־מָקוֹם אַתֶּם וּבֵיתְכֶם כִּי־שָׂכָר הוּא לָכֶם חֵלֶף עֲבֹדַתְכֶם בְּאֹהֶל מוֹעֵד׃
וְלֹא־תִשְׂאוּ עָלָיו חֵטְא בַּהֲרִימְכֶם אֶת־חֶלְבּוֹ מִמֶּנּוּ וְאֶת־קָדְשֵׁי בְנֵי־יִשְׂרָאֵל לֹא תְחַלְּלוּ וְלֹא תָמוּתוּ׃

Chapter 19

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן לֵאמֹר׃
זֹאת חֻקַּת הַתּוֹרָה אֲשֶׁר־צִוָּה יְהוָה לֵאמֹר דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְיִקְחוּ אֵלֶיךָ פָרָה אֲדֻמָּה תְּמִימָה אֲשֶׁר אֵין־בָּהּ מוּם אֲשֶׁר לֹא־עָלָה עָלֶיהָ עֹל׃
וּנְתַתֶּם אֹתָהּ אֶל־אֶלְעָזָר הַכֹּהֵן וְהוֹצִיא אֹתָהּ אֶל־מִחוּץ לַמַּחֲנֶה וְשָׁחַט אֹתָהּ לְפָנָיו׃
וְלָקַח אֶלְעָזָר הַכֹּהֵן מִדָּמָהּ בְּאֶצְבָּעוֹ וְהִזָּה אֶל־נֹכַח פְּנֵי אֹהֶל־מוֹעֵד מִדָּמָהּ שֶׁבַע פְּעָמִים׃
וְשָׂרַף אֶת־הַפָּרָה לְעֵינָיו אֶת־עֹרָהּ וְאֶת־בְּשָׂרָהּ וְאֶת־דָּמָהּ עַל־פִּרְשָׁהּ יִשְׂרֹף׃
וְלָקַח הַכֹּהֵן עֵץ אֶרֶז וְאֵזוֹב וּשְׁנִי תוֹלָעַת וְהִשְׁלִיךְ אֶל־תּוֹךְ שְׂרֵפַת הַפָּרָה׃
וְכִבֶּס בְּגָדָיו הַכֹּהֵן וְרָחַץ בְּשָׂרוֹ בַּמַּיִם וְאַחַר יָבוֹא אֶל־הַמַּחֲנֶה וְטָמֵא הַכֹּהֵן עַד־הָעָרֶב׃
וְהַשֹּׂרֵף אֹתָהּ יְכַבֵּס בְּגָדָיו בַּמַּיִם וְרָחַץ בְּשָׂרוֹ בַּמָּיִם וְטָמֵא עַד־הָעָרֶב׃
וְאָסַף אִישׁ טָהוֹר אֵת אֵפֶר הַפָּרָה וְהִנִּיחַ מִחוּץ לַמַּחֲנֶה בְּמָקוֹם טָהוֹר וְהָיְתָה לַעֲדַת בְּנֵי־יִשְׂרָאֵל לְמִשְׁמֶרֶת לְמֵי נִדָּה חַטָּאת הִוא׃
וְכִבֶּס הָאֹסֵף אֶת־אֵפֶר הַפָּרָה אֶת־בְּגָדָיו וְטָמֵא עַד־הָעָרֶב וְהָיְתָה לִבְנֵי יִשְׂרָאֵל וְלַגֵּר הַגָּר בְּתוֹכָם לְחֻקַּת עוֹלָם׃
הַנֹּגֵעַ בְּמֵת לְכָל־נֶפֶשׁ אָדָם וְטָמֵא שִׁבְעַת יָמִים׃
הוּא יִתְחַטָּא־בוֹ בַּיּוֹם הַשְּׁלִישִׁי וּבַיּוֹם הַשְּׁבִיעִי יִטְהָר וְאִם־לֹא יִתְחַטָּא בַּיּוֹם הַשְּׁלִישִׁי וּבַיּוֹם הַשְּׁבִיעִי לֹא יִטְהָר׃
כָּל־הַנֹּגֵעַ בְּמֵת בְּנֶפֶשׁ הָאָדָם אֲשֶׁר־יָמוּת וְלֹא יִתְחַטָּא אֶת־מִשְׁכַּן יְהוָה טִמֵּא וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מִיִּשְׂרָאֵל כִּי מֵי נִדָּה לֹא־זֹרַק עָלָיו טָמֵא יִהְיֶה עוֹד טֻמְאָתוֹ בוֹ׃
זֹאת הַתּוֹרָה אָדָם כִּי־יָמוּת בְּאֹהֶל כָּל־הַבָּא אֶל־הָאֹהֶל וְכָל־אֲשֶׁר בָּאֹהֶל יִטְמָא שִׁבְעַת יָמִים׃
וְכֹל כְּלִי פָתוּחַ אֲשֶׁר אֵין־צָמִיד פָּתִיל עָלָיו טָמֵא הוּא׃
וְכֹל אֲשֶׁר־יִגַּע עַל־פְּנֵי הַשָּׂדֶה בַּחֲלַל־חֶרֶב אוֹ בְמֵת אוֹ־בְעֶצֶם אָדָם אוֹ בְקָבֶר יִטְמָא שִׁבְעַת יָמִים׃
וְלָקְחוּ לַטָּמֵא מֵעֲפַר שְׂרֵפַת הַחַטָּאת וְנָתַן עָלָיו מַיִם חַיִּים אֶל־כֶּלִי׃
וְלָקַח אֵזוֹב וְטָבַל בַּמַּיִם אִישׁ טָהוֹר וְהִזָּה עַל־הָאֹהֶל וְעַל־כָּל־הַכֵּלִים וְעַל־הַנְּפָשׁוֹת אֲשֶׁר הָיוּ־שָׁם וְעַל־הַנֹּגֵעַ בַּעֶצֶם אוֹ בֶחָלָל אוֹ בַמֵּת אוֹ בַקָּבֶר׃
וְהִזָּה הַטָּהֹר עַל־הַטָּמֵא בַּיּוֹם הַשְּׁלִישִׁי וּבַיּוֹם הַשְּׁבִיעִי וְחִטְּאוֹ בַּיּוֹם הַשְּׁבִיעִי וְכִבֶּס בְּגָדָיו וְרָחַץ בַּמַּיִם וְטָהֵר בָּעָרֶב׃
וְאִישׁ אֲשֶׁר־יִטְמָא וְלֹא יִתְחַטָּא וְנִכְרְתָה הַנֶּפֶשׁ הַהִוא מִתּוֹךְ הַקָּהָל כִּי אֶת־מִקְדַּשׁ יְהוָה טִמֵּא מֵי נִדָּה לֹא־זֹרַק עָלָיו טָמֵא הוּא׃
וְהָיְתָה לָּהֶם לְחֻקַּת עוֹלָם וּמַזֵּה מֵי־הַנִּדָּה יְכַבֵּס בְּגָדָיו וְהַנֹּגֵעַ בְּמֵי הַנִּדָּה יִטְמָא עַד־הָעָרֶב׃
וְכֹל אֲשֶׁר־יִגַּע־בּוֹ הַטָּמֵא יִטְמָא וְהַנֶּפֶשׁ הַנֹּגַעַת תִּטְמָא עַד־הָעָרֶב׃

Chapter 20

וַיָּבֹאוּ בְנֵי־יִשְׂרָאֵל כָּל־הָעֵדָה מִדְבַּר־צִן בַּחֹדֶשׁ הָרִאשׁוֹן וַיֵּשֶׁב הָעָם בְּקָדֵשׁ וַתָּמָת שָׁם מִרְיָם וַתִּקָּבֵר שָׁם׃
וְלֹא־הָיָה מַיִם לָעֵדָה וַיִּקָּהֲלוּ עַל־מֹשֶׁה וְעַל־אַהֲרֹן׃
וַיָּרֶב הָעָם עִם־מֹשֶׁה וַיֹּאמְרוּ לֵאמֹר וְלוּ גָוַעְנוּ בִּגְוַע אַחֵינוּ לִפְנֵי יְהוָה׃
וְלָמָה הֲבֵאתֶם אֶת־קְהַל יְהוָה אֶל־הַמִּדְבָּר הַזֶּה לָמוּת שָׁם אֲנַחְנוּ וּבְעִירֵנוּ׃
וְלָמָה הֶעֱלִיתֻנוּ מִמִּצְרַיִם לְהָבִיא אֹתָנוּ אֶל־הַמָּקוֹם הָרָע הַזֶּה לֹא מְקוֹם זֶרַע וּתְאֵנָה וְגֶפֶן וְרִמּוֹן וּמַיִם אַיִן לִשְׁתּוֹת׃
וַיָּבֹא מֹשֶׁה וְאַהֲרֹן מִפְּנֵי הַקָּהָל אֶל־פֶּתַח אֹהֶל מוֹעֵד וַיִּפְּלוּ עַל־פְּנֵיהֶם וַיֵּרָא כְבוֹד־יְהוָה אֲלֵיהֶם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
קַח אֶת־הַמַּטֶּה וְהַקְהֵל אֶת־הָעֵדָה אַתָּה וְאַהֲרֹן אָחִיךָ וְדִבַּרְתֶּם אֶל־הַסֶּלַע לְעֵינֵיהֶם וְנָתַן מֵימָיו וְהוֹצֵאתָ לָהֶם מַיִם מִן־הַסֶּלַע וְהִשְׁקִיתָ אֶת־הָעֵדָה וְאֶת־בְּעִירָם׃
וַיִּקַּח מֹשֶׁה אֶת־הַמַּטֶּה מִלִּפְנֵי יְהוָה כַּאֲשֶׁר צִוָּהוּ׃
וַיַּקְהִלוּ מֹשֶׁה וְאַהֲרֹן אֶת־הַקָּהָל אֶל־פְּנֵי הַסָּלַע וַיֹּאמֶר לָהֶם שִׁמְעוּ־נָא הַמֹּרִים הֲמִן־הַסֶּלַע הַזֶּה נוֹצִיא לָכֶם מָיִם׃
וַיָּרֶם מֹשֶׁה אֶת־יָדוֹ וַיַּךְ אֶת־הַסֶּלַע בְּמַטֵּהוּ פַּעֲמָיִם וַיֵּצְאוּ מַיִם רַבִּים וַתֵּשְׁתְּ הָעֵדָה וּבְעִירָם׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן יַעַן לֹא־הֶאֱמַנְתֶּם בִּי לְהַקְדִּישֵׁנִי לְעֵינֵי בְּנֵי יִשְׂרָאֵל לָכֵן לֹא תָבִיאוּ אֶת־הַקָּהָל הַזֶּה אֶל־הָאָרֶץ אֲשֶׁר־נָתַתִּי לָהֶם׃
הֵמָּה מֵי מְרִיבָה אֲשֶׁר־רָבוּ בְנֵי־יִשְׂרָאֵל אֶת־יְהוָה וַיִּקָּדֵשׁ בָּם׃
וַיִּשְׁלַח מֹשֶׁה מַלְאָכִים מִקָּדֵשׁ אֶל־מֶלֶךְ אֱדוֹם כֹּה אָמַר אָחִיךָ יִשְׂרָאֵל אַתָּה יָדַעְתָּ אֵת כָּל־הַתְּלָאָה אֲשֶׁר מְצָאָתְנוּ׃
וַיֵּרְדוּ אֲבֹתֵינוּ מִצְרַיְמָה וַנֵּשֶׁב בְּמִצְרַיִם יָמִים רַבִּים וַיָּרֵעוּ לָנוּ מִצְרַיִם וְלַאֲבֹתֵינוּ׃
וַנִּצְעַק אֶל־יְהוָה וַיִּשְׁמַע קֹלֵנוּ וַיִּשְׁלַח מַלְאָךְ וַיֹּצִאֵנוּ מִמִּצְרָיִם וְהִנֵּה אֲנַחְנוּ בְקָדֵשׁ עִיר קְצֵה גְבוּלֶךָ׃
נַעְבְּרָה־נָּא בְאַרְצֶךָ לֹא נַעֲבֹר בְּשָׂדֶה וּבְכֶרֶם וְלֹא נִשְׁתֶּה מֵי בְאֵר דֶּרֶךְ הַמֶּלֶךְ נֵלֵךְ לֹא נִטֶּה יָמִין וּשְׂמֹאול עַד אֲשֶׁר־נַעֲבֹר גְּבוּלֶךָ׃
וַיֹּאמֶר אֵלָיו אֱדוֹם לֹא תַעֲבֹר בִּי פֶּן־בַּחֶרֶב אֵצֵא לִקְרָאתֶךָ׃
וַיֹּאמְרוּ אֵלָיו בְּנֵי־יִשְׂרָאֵל בַּמְסִלָּה נַעֲלֶה וְאִם־מֵימֶיךָ נִשְׁתֶּה אֲנִי וּמִקְנַי וְנָתַתִּי מִכְרָם רַק אֵין־דָּבָר בְּרַגְלַי אֶעֱבֹרָה׃
וַיֹּאמֶר לֹא תַעֲבֹר וַיֵּצֵא אֱדוֹם לִקְרָאתוֹ בְּעַם כָּבֵד וּבְיָד חֲזָקָה׃
וַיְמָאֵן אֱדוֹם נְתֹן אֶת־יִשְׂרָאֵל עֲבֹר בִּגְבֻלוֹ וַיֵּט יִשְׂרָאֵל מֵעָלָיו׃
וַיִּסְעוּ מִקָּדֵשׁ וַיָּבֹאוּ בְנֵי־יִשְׂרָאֵל כָּל־הָעֵדָה הֹר הָהָר׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאֶל־אַהֲרֹן בְּהֹר הָהָר עַל־גְּבוּל אֶרֶץ־אֱדוֹם לֵאמֹר׃
יֵאָסֵף אַהֲרֹן אֶל־עַמָּיו כִּי לֹא יָבֹא אֶל־הָאָרֶץ אֲשֶׁר נָתַתִּי לִבְנֵי יִשְׂרָאֵל עַל אֲשֶׁר־מְרִיתֶם אֶת־פִּי לְמֵי מְרִיבָה׃
קַח אֶת־אַהֲרֹן וְאֶת־אֶלְעָזָר בְּנוֹ וְהַעַל אֹתָם הֹר הָהָר׃
וְהַפְשֵׁט אֶת־אַהֲרֹן אֶת־בְּגָדָיו וְהִלְבַּשְׁתָּם אֶת־אֶלְעָזָר בְּנוֹ וְאַהֲרֹן יֵאָסֵף וּמֵת שָׁם׃
וַיַּעַשׂ מֹשֶׁה כַּאֲשֶׁר צִוָּה יְהוָה וַיַּעֲלוּ אֶל־הֹר הָהָר לְעֵינֵי כָּל־הָעֵדָה׃
וַיַּפְשֵׁט מֹשֶׁה אֶת־אַהֲרֹן אֶת־בְּגָדָיו וַיַּלְבֵּשׁ אֹתָם אֶת־אֶלְעָזָר בְּנוֹ וַיָּמָת אַהֲרֹן שָׁם בְּרֹאשׁ הָהָר וַיֵּרֶד מֹשֶׁה וְאֶלְעָזָר מִן־הָהָר׃
וַיִּרְאוּ כָּל־הָעֵדָה כִּי גָוַע אַהֲרֹן וַיִּבְכּוּ אֶת־אַהֲרֹן שְׁלֹשִׁים יוֹם כֹּל בֵּית יִשְׂרָאֵל׃

Chapter 21

וַיִּשְׁמַע הַכְּנַעֲנִי מֶלֶךְ־עֲרָד יֹשֵׁב הַנֶּגֶב כִּי בָּא יִשְׂרָאֵל דֶּרֶךְ הָאֲתָרִים וַיִּלָּחֶם בְּיִשְׂרָאֵל וַיִּשְׁבְּ מִמֶּנּוּ שֶׁבִי׃
וַיִּדַּר יִשְׂרָאֵל נֶדֶר לַיהוָה וַיֹּאמַר אִם־נָתֹן תִּתֵּן אֶת־הָעָם הַזֶּה בְּיָדִי וְהַחֲרַמְתִּי אֶת־עָרֵיהֶם׃
וַיִּשְׁמַע יְהוָה בְּקוֹל יִשְׂרָאֵל וַיִּתֵּן אֶת־הַכְּנַעֲנִי וַיַּחֲרֵם אֶתְהֶם וְאֶת־עָרֵיהֶם וַיִּקְרָא שֵׁם־הַמָּקוֹם חָרְמָה׃
וַיִּסְעוּ מֵהֹר הָהָר דֶּרֶךְ יַם־סוּף לִסְבֹב אֶת־אֶרֶץ אֱדוֹם וַתִּקְצַר נֶפֶשׁ־הָעָם בַּדָּרֶךְ׃
וַיְדַבֵּר הָעָם בֵּאלֹהִים וּבְמֹשֶׁה לָמָה הֶעֱלִיתֻנוּ מִמִּצְרַיִם לָמוּת בַּמִּדְבָּר כִּי אֵין לֶחֶם וְאֵין מַיִם וְנַפְשֵׁנוּ קָצָה בַּלֶּחֶם הַקְּלֹקֵל׃
וַיְשַׁלַּח יְהוָה בָּעָם אֵת הַנְּחָשִׁים הַשְּׂרָפִים וַיְנַשְּׁכוּ אֶת־הָעָם וַיָּמָת עַם־רָב מִיִּשְׂרָאֵל׃
וַיָּבֹא הָעָם אֶל־מֹשֶׁה וַיֹּאמְרוּ חָטָאנוּ כִּי־דִבַּרְנוּ בַיהוָה וָבָךְ הִתְפַּלֵּל אֶל־יְהוָה וְיָסֵר מֵעָלֵינוּ אֶת־הַנָּחָשׁ וַיִּתְפַּלֵּל מֹשֶׁה בְּעַד הָעָם׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עֲשֵׂה לְךָ שָׂרָף וְשִׂים אֹתוֹ עַל־נֵס וְהָיָה כָּל־הַנָּשׁוּךְ וְרָאָה אֹתוֹ וָחָי׃
וַיַּעַשׂ מֹשֶׁה נְחַשׁ נְחֹשֶׁת וַיְשִׂמֵהוּ עַל־הַנֵּס וְהָיָה אִם־נָשַׁךְ הַנָּחָשׁ אֶת־אִישׁ וְהִבִּיט אֶל־נְחַשׁ הַנְּחֹשֶׁת וָחָי׃
וַיִּסְעוּ בְּנֵי יִשְׂרָאֵל וַיַּחֲנוּ בְּאֹבֹת׃
וַיִּסְעוּ מֵאֹבֹת וַיַּחֲנוּ בְּעִיֵּי הָעֲבָרִים בַּמִּדְבָּר אֲשֶׁר עַל־פְּנֵי מוֹאָב מִמִּזְרַח הַשָּׁמֶשׁ׃
מִשָּׁם נָסָעוּ וַיַּחֲנוּ בְּנַחַל זָרֶד׃
מִשָּׁם נָסָעוּ וַיַּחֲנוּ מֵעֵבֶר אַרְנוֹן אֲשֶׁר בַּמִּדְבָּר הַיֹּצֵא מִגְּבוּל הָאֱמֹרִי כִּי אַרְנוֹן גְּבוּל מוֹאָב בֵּין מוֹאָב וּבֵין הָאֱמֹרִי׃
עַל־כֵּן יֵאָמַר בְּסֵפֶר מִלְחֲמֹת יְהוָה אֶת־וָהֵב בְּסוּפָה וְאֶת־הַנְּחָלִים אַרְנוֹן׃
וְאֶשֶׁד הַנְּחָלִים אֲשֶׁר נָטָה לְשֶׁבֶת עָר וְנִשְׁעַן לִגְבוּל מוֹאָב׃
וּמִשָּׁם בְּאֵרָה הִוא הַבְּאֵר אֲשֶׁר אָמַר יְהוָה לְמֹשֶׁה אֱסֹף אֶת־הָעָם וְאֶתְּנָה לָהֶם מָיִם׃
אָז יָשִׁיר יִשְׂרָאֵל אֶת־הַשִּׁירָה הַזֹּאת עֲלִי בְאֵר עֱנוּ־לָהּ׃
בְּאֵר חֲפָרוּהָ שָׂרִים כָּרוּהָ נְדִיבֵי הָעָם בִּמְחֹקֵק בְּמִשְׁעֲנֹתָם וּמִמִּדְבָּר מַתָּנָה׃
וּמִמַּתָּנָה נַחֲלִיאֵל וּמִנַּחֲלִיאֵל בָּמוֹת׃
וּמִבָּמוֹת הַגַּיְא אֲשֶׁר בִּשְׂדֵה מוֹאָב רֹאשׁ הַפִּסְגָּה וְנִשְׁקָפָה עַל־פְּנֵי הַיְשִׁימֹן׃
וַיִּשְׁלַח יִשְׂרָאֵל מַלְאָכִים אֶל־סִיחֹן מֶלֶךְ־הָאֱמֹרִי לֵאמֹר׃
אֶעְבְּרָה בְאַרְצֶךָ לֹא נִטֶּה בְּשָׂדֶה וּבְכֶרֶם לֹא נִשְׁתֶּה מֵי בְאֵר בְּדֶרֶךְ הַמֶּלֶךְ נֵלֵךְ עַד אֲשֶׁר־נַעֲבֹר גְּבֻלֶךָ׃
וְלֹא־נָתַן סִיחֹן אֶת־יִשְׂרָאֵל עֲבֹר בִּגְבֻלוֹ וַיֶּאֱסֹף סִיחֹן אֶת־כָּל־עַמּוֹ וַיֵּצֵא לִקְרַאת יִשְׂרָאֵל הַמִּדְבָּרָה וַיָּבֹא יָהְצָה וַיִּלָּחֶם בְּיִשְׂרָאֵל׃
וַיַּכֵּהוּ יִשְׂרָאֵל לְפִי־חָרֶב וַיִּירַשׁ אֶת־אַרְצוֹ מֵאַרְנֹן עַד־יַבֹּק עַד־בְּנֵי עַמּוֹן כִּי עַז גְּבוּל בְּנֵי עַמּוֹן׃
וַיִּקַּח יִשְׂרָאֵל אֵת כָּל־הֶעָרִים הָאֵלֶּה וַיֵּשֶׁב יִשְׂרָאֵל בְּכָל־עָרֵי הָאֱמֹרִי בְּחֶשְׁבּוֹן וּבְכָל־בְּנֹתֶיהָ׃
כִּי חֶשְׁבּוֹן עִיר סִיחֹן מֶלֶךְ הָאֱמֹרִי הִוא וְהוּא נִלְחַם בְּמֶלֶךְ מוֹאָב הָרִאשׁוֹן וַיִּקַּח אֶת־כָּל־אַרְצוֹ מִיָּדוֹ עַד־אַרְנֹן׃
עַל־כֵּן יֹאמְרוּ הַמֹּשְׁלִים בֹּאוּ חֶשְׁבּוֹן תִּבָּנֶה וְתִכּוֹנֵן עִיר סִיחוֹן׃
כִּי־אֵשׁ יָצְאָה מֵחֶשְׁבּוֹן לֶהָבָה מִקִּרְיַת סִיחֹן אָכְלָה עָר מוֹאָב בַּעֲלֵי בָּמוֹת אַרְנֹן׃
אוֹי־לְךָ מוֹאָב אָבַדְתָּ עַם־כְּמוֹשׁ נָתַן בָּנָיו פְּלֵיטִם וּבְנֹתָיו בַּשְּׁבִית לְמֶלֶךְ אֱמֹרִי סִיחוֹן׃
וַנִּירָם אָבַד חֶשְׁבּוֹן עַד־דִּיבוֹן וַנַּשִּׁים עַד־נֹפַח אֲשֶׁר עַד־מֵידְבָא׃
וַיֵּשֶׁב יִשְׂרָאֵל בְּאֶרֶץ הָאֱמֹרִי׃
וַיִּשְׁלַח מֹשֶׁה לְרַגֵּל אֶת־יַעְזֵר וַיִּלְכְּדוּ בְּנֹתֶיהָ ויירש [וַיּוֹרֶשׁ] אֶת־הָאֱמֹרִי אֲשֶׁר־שָׁם׃
וַיִּפְנוּ וַיַּעֲלוּ דֶּרֶךְ הַבָּשָׁן וַיֵּצֵא עוֹג מֶלֶךְ־הַבָּשָׁן לִקְרָאתָם הוּא וְכָל־עַמּוֹ לַמִּלְחָמָה אֶדְרֶעִי׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה אַל־תִּירָא אֹתוֹ כִּי בְיָדְךָ נָתַתִּי אֹתוֹ וְאֶת־כָּל־עַמּוֹ וְאֶת־אַרְצוֹ וְעָשִׂיתָ לּוֹ כַּאֲשֶׁר עָשִׂיתָ לְסִיחֹן מֶלֶךְ הָאֱמֹרִי אֲשֶׁר יוֹשֵׁב בְּחֶשְׁבּוֹן׃
וַיַּכּוּ אֹתוֹ וְאֶת־בָּנָיו וְאֶת־כָּל־עַמּוֹ עַד־בִּלְתִּי הִשְׁאִיר־לוֹ שָׂרִיד וַיִּירְשׁוּ אֶת־אַרְצוֹ׃

Chapter 22

וַיִּסְעוּ בְּנֵי יִשְׂרָאֵל וַיַּחֲנוּ בְּעַרְבוֹת מוֹאָב מֵעֵבֶר לְיַרְדֵּן יְרֵחוֹ׃
וַיַּרְא בָּלָק בֶּן־צִפּוֹר אֵת כָּל־אֲשֶׁר־עָשָׂה יִשְׂרָאֵל לָאֱמֹרִי׃
וַיָּגָר מוֹאָב מִפְּנֵי הָעָם מְאֹד כִּי רַב־הוּא וַיָּקָץ מוֹאָב מִפְּנֵי בְּנֵי יִשְׂרָאֵל׃
וַיֹּאמֶר מוֹאָב אֶל־זִקְנֵי מִדְיָן עַתָּה יְלַחֲכוּ הַקָּהָל אֶת־כָּל־סְבִיבֹתֵינוּ כִּלְחֹךְ הַשּׁוֹר אֵת יֶרֶק הַשָּׂדֶה וּבָלָק בֶּן־צִפּוֹר מֶלֶךְ לְמוֹאָב בָּעֵת הַהִוא׃
וַיִּשְׁלַח מַלְאָכִים אֶל־בִּלְעָם בֶּן־בְּעוֹר פְּתוֹרָה אֲשֶׁר עַל־הַנָּהָר אֶרֶץ בְּנֵי־עַמּוֹ לִקְרֹא־לוֹ לֵאמֹר הִנֵּה עַם יָצָא מִמִּצְרַיִם הִנֵּה כִסָּה אֶת־עֵין הָאָרֶץ וְהוּא יֹשֵׁב מִמֻּלִי׃
וְעַתָּה לְכָה־נָּא אָרָה־לִּי אֶת־הָעָם הַזֶּה כִּי־עָצוּם הוּא מִמֶּנִּי אוּלַי אוּכַל נַכֶּה־בּוֹ וַאֲגָרְשֶׁנּוּ מִן־הָאָרֶץ כִּי יָדַעְתִּי אֵת אֲשֶׁר־תְּבָרֵךְ מְבֹרָךְ וַאֲשֶׁר תָּאֹר יוּאָר׃
וַיֵּלְכוּ זִקְנֵי מוֹאָב וְזִקְנֵי מִדְיָן וּקְסָמִים בְּיָדָם וַיָּבֹאוּ אֶל־בִּלְעָם וַיְדַבְּרוּ אֵלָיו דִּבְרֵי בָלָק׃
וַיֹּאמֶר אֲלֵיהֶם לִינוּ פֹה הַלַּיְלָה וַהֲשִׁבֹתִי אֶתְכֶם דָּבָר כַּאֲשֶׁר יְדַבֵּר יְהוָה אֵלָי וַיֵּשְׁבוּ שָׂרֵי־מוֹאָב עִם־בִּלְעָם׃
וַיָּבֹא אֱלֹהִים אֶל־בִּלְעָם וַיֹּאמֶר מִי הָאֲנָשִׁים הָאֵלֶּה עִמָּךְ׃
וַיֹּאמֶר בִּלְעָם אֶל־הָאֱלֹהִים בָּלָק בֶּן־צִפֹּר מֶלֶךְ מוֹאָב שָׁלַח אֵלָי׃
הִנֵּה הָעָם הַיֹּצֵא מִמִּצְרַיִם וַיְכַס אֶת־עֵין הָאָרֶץ עַתָּה לְכָה קָבָה־לִּי אֹתוֹ אוּלַי אוּכַל לְהִלָּחֶם בּוֹ וְגֵרַשְׁתִּיו׃
וַיֹּאמֶר אֱלֹהִים אֶל־בִּלְעָם לֹא תֵלֵךְ עִמָּהֶם לֹא תָאֹר אֶת־הָעָם כִּי בָרוּךְ הוּא׃
וַיָּקָם בִּלְעָם בַּבֹּקֶר וַיֹּאמֶר אֶל־שָׂרֵי בָלָק לְכוּ אֶל־אַרְצְכֶם כִּי מֵאֵן יְהוָה לְתִתִּי לַהֲלֹךְ עִמָּכֶם׃
וַיָּקוּמוּ שָׂרֵי מוֹאָב וַיָּבֹאוּ אֶל־בָּלָק וַיֹּאמְרוּ מֵאֵן בִּלְעָם הֲלֹךְ עִמָּנוּ׃
וַיֹּסֶף עוֹד בָּלָק שְׁלֹחַ שָׂרִים רַבִּים וְנִכְבָּדִים מֵאֵלֶּה׃
וַיָּבֹאוּ אֶל־בִּלְעָם וַיֹּאמְרוּ לוֹ כֹּה אָמַר בָּלָק בֶּן־צִפּוֹר אַל־נָא תִמָּנַע מֵהֲלֹךְ אֵלָי׃
כִּי־כַבֵּד אֲכַבֶּדְךָ מְאֹד וְכֹל אֲשֶׁר־תֹּאמַר אֵלַי אֶעֱשֶׂה וּלְכָה־נָּא קָבָה־לִּי אֵת הָעָם הַזֶּה׃
וַיַּעַן בִּלְעָם וַיֹּאמֶר אֶל־עַבְדֵי בָלָק אִם־יִתֶּן־לִי בָלָק מְלֹא בֵיתוֹ כֶּסֶף וְזָהָב לֹא אוּכַל לַעֲבֹר אֶת־פִּי יְהוָה אֱלֹהָי לַעֲשׂוֹת קְטַנָּה אוֹ גְדוֹלָה׃
וְעַתָּה שְׁבוּ נָא בָזֶה גַּם־אַתֶּם הַלָּיְלָה וְאֵדְעָה מַה־יֹּסֵף יְהוָה דַּבֵּר עִמִּי׃
וַיָּבֹא אֱלֹהִים אֶל־בִּלְעָם לַיְלָה וַיֹּאמֶר לוֹ אִם־לִקְרֹא לְךָ בָּאוּ הָאֲנָשִׁים קוּם לֵךְ אִתָּם וְאַךְ אֶת־הַדָּבָר אֲשֶׁר־אֲדַבֵּר אֵלֶיךָ אֹתוֹ תַעֲשֶׂה׃
וַיָּקָם בִּלְעָם בַּבֹּקֶר וַיַּחֲבֹשׁ אֶת־אֲתֹנוֹ וַיֵּלֶךְ עִם־שָׂרֵי מוֹאָב׃
וַיִּחַר־אַף אֱלֹהִים כִּי־הוֹלֵךְ הוּא וַיִּתְיַצֵּב מַלְאַךְ יְהוָה בַּדֶּרֶךְ לְשָׂטָן לוֹ וְהוּא רֹכֵב עַל־אֲתֹנוֹ וּשְׁנֵי נְעָרָיו עִמּוֹ׃
וַתֵּרֶא הָאָתוֹן אֶת־מַלְאַךְ יְהוָה נִצָּב בַּדֶּרֶךְ וְחַרְבּוֹ שְׁלוּפָה בְּיָדוֹ וַתֵּט הָאָתוֹן מִן־הַדֶּרֶךְ וַתֵּלֶךְ בַּשָּׂדֶה וַיַּךְ בִּלְעָם אֶת־הָאָתוֹן לְהַטֹּתָהּ הַדָּרֶךְ׃
וַיַּעֲמֹד מַלְאַךְ יְהוָה בְּמִשְׁעוֹל הַכְּרָמִים גָּדֵר מִזֶּה וְגָדֵר מִזֶּה׃
וַתֵּרֶא הָאָתוֹן אֶת־מַלְאַךְ יְהוָה וַתִּלָּחֵץ אֶל־הַקִּיר וַתִּלְחַץ אֶת־רֶגֶל בִּלְעָם אֶל־הַקִּיר וַיֹּסֶף לְהַכֹּתָהּ׃
וַיּוֹסֶף מַלְאַךְ־יְהוָה עֲבוֹר וַיַּעֲמֹד בְּמָקוֹם צָר אֲשֶׁר אֵין־דֶּרֶךְ לִנְטוֹת יָמִין וּשְׂמֹאול׃
וַתֵּרֶא הָאָתוֹן אֶת־מַלְאַךְ יְהוָה וַתִּרְבַּץ תַּחַת בִּלְעָם וַיִּחַר־אַף בִּלְעָם וַיַּךְ אֶת־הָאָתוֹן בַּמַּקֵּל׃
וַיִּפְתַּח יְהוָה אֶת־פִּי הָאָתוֹן וַתֹּאמֶר לְבִלְעָם מֶה־עָשִׂיתִי לְךָ כִּי הִכִּיתַנִי זֶה שָׁלֹשׁ רְגָלִים׃
וַיֹּאמֶר בִּלְעָם לָאָתוֹן כִּי הִתְעַלַּלְתְּ בִּי לוּ יֶשׁ־חֶרֶב בְּיָדִי כִּי עַתָּה הֲרַגְתִּיךְ׃
וַתֹּאמֶר הָאָתוֹן אֶל־בִּלְעָם הֲלוֹא אָנֹכִי אֲתֹנְךָ אֲשֶׁר־רָכַבְתָּ עָלַי מֵעוֹדְךָ עַד־הַיּוֹם הַזֶּה הַהַסְכֵּן הִסְכַּנְתִּי לַעֲשׂוֹת לְךָ כֹּה וַיֹּאמֶר לֹא׃
וַיְגַל יְהוָה אֶת־עֵינֵי בִלְעָם וַיַּרְא אֶת־מַלְאַךְ יְהוָה נִצָּב בַּדֶּרֶךְ וְחַרְבּוֹ שְׁלֻפָה בְּיָדוֹ וַיִּקֹּד וַיִּשְׁתַּחוּ לְאַפָּיו׃
וַיֹּאמֶר אֵלָיו מַלְאַךְ יְהוָה עַל־מָה הִכִּיתָ אֶת־אֲתֹנְךָ זֶה שָׁלוֹשׁ רְגָלִים הִנֵּה אָנֹכִי יָצָאתִי לְשָׂטָן כִּי־יָרַט הַדֶּרֶךְ לְנֶגְדִּי׃
וַתִּרְאַנִי הָאָתוֹן וַתֵּט לְפָנַי זֶה שָׁלֹשׁ רְגָלִים אוּלַי נָטְתָה מִפָּנַי כִּי עַתָּה גַּם־אֹתְכָה הָרַגְתִּי וְאוֹתָהּ הֶחֱיֵיתִי׃
וַיֹּאמֶר בִּלְעָם אֶל־מַלְאַךְ יְהוָה חָטָאתִי כִּי לֹא יָדַעְתִּי כִּי אַתָּה נִצָּב לִקְרָאתִי בַּדָּרֶךְ וְעַתָּה אִם־רַע בְּעֵינֶיךָ אָשׁוּבָה לִּי׃
וַיֹּאמֶר מַלְאַךְ יְהוָה אֶל־בִּלְעָם לֵךְ עִם־הָאֲנָשִׁים וְאֶפֶס אֶת־הַדָּבָר אֲשֶׁר־אֲדַבֵּר אֵלֶיךָ אֹתוֹ תְדַבֵּר וַיֵּלֶךְ בִּלְעָם עִם־שָׂרֵי בָלָק׃
וַיִּשְׁמַע בָּלָק כִּי בָא בִלְעָם וַיֵּצֵא לִקְרָאתוֹ אֶל־עִיר מוֹאָב אֲשֶׁר עַל־גְּבוּל אַרְנֹן אֲשֶׁר בִּקְצֵה הַגְּבוּל׃
וַיֹּאמֶר בָּלָק אֶל־בִּלְעָם הֲלֹא שָׁלֹחַ שָׁלַחְתִּי אֵלֶיךָ לִקְרֹא־לָךְ לָמָּה לֹא־הָלַכְתָּ אֵלָי הַאֻמְנָם לֹא אוּכַל כַּבְּדֶךָ׃
וַיֹּאמֶר בִּלְעָם אֶל־בָּלָק הִנֵּה־בָאתִי אֵלֶיךָ עַתָּה הֲיָכוֹל אוּכַל דַּבֵּר מְאוּמָה הַדָּבָר אֲשֶׁר יָשִׂים אֱלֹהִים בְּפִי אֹתוֹ אֲדַבֵּר׃
וַיֵּלֶךְ בִּלְעָם עִם־בָּלָק וַיָּבֹאוּ קִרְיַת חֻצוֹת׃
וַיִּזְבַּח בָּלָק בָּקָר וָצֹאן וַיְשַׁלַּח לְבִלְעָם וְלַשָּׂרִים אֲשֶׁר אִתּוֹ׃
וַיְהִי בַבֹּקֶר וַיִּקַּח בָּלָק אֶת־בִּלְעָם וַיַּעֲלֵהוּ בָּמוֹת בָּעַל וַיַּרְא מִשָּׁם קְצֵה הָעָם׃

Chapter 23

וַיֹּאמֶר בִּלְעָם אֶל־בָּלָק בְּנֵה־לִי בָזֶה שִׁבְעָה מִזְבְּחֹת וְהָכֵן לִי בָּזֶה שִׁבְעָה פָרִים וְשִׁבְעָה אֵילִים׃
וַיַּעַשׂ בָּלָק כַּאֲשֶׁר דִּבֶּר בִּלְעָם וַיַּעַל בָּלָק וּבִלְעָם פָּר וָאַיִל בַּמִּזְבֵּחַ׃
וַיֹּאמֶר בִּלְעָם לְבָלָק הִתְיַצֵּב עַל־עֹלָתֶךָ וְאֵלְכָה אוּלַי יִקָּרֵה יְהוָה לִקְרָאתִי וּדְבַר מַה־יַּרְאֵנִי וְהִגַּדְתִּי לָךְ וַיֵּלֶךְ שֶׁפִי׃
וַיִּקָּר אֱלֹהִים אֶל־בִּלְעָם וַיֹּאמֶר אֵלָיו אֶת־שִׁבְעַת הַמִּזְבְּחֹת עָרַכְתִּי וָאַעַל פָּר וָאַיִל בַּמִּזְבֵּחַ׃
וַיָּשֶׂם יְהוָה דָּבָר בְּפִי בִלְעָם וַיֹּאמֶר שׁוּב אֶל־בָּלָק וְכֹה תְדַבֵּר׃
וַיָּשָׁב אֵלָיו וְהִנֵּה נִצָּב עַל־עֹלָתוֹ הוּא וְכָל־שָׂרֵי מוֹאָב׃
וַיִּשָּׂא מְשָׁלוֹ וַיֹּאמַר מִן־אֲרָם יַנְחֵנִי בָלָק מֶלֶךְ־מוֹאָב מֵהַרְרֵי־קֶדֶם לְכָה אָרָה־לִּי יַעֲקֹב וּלְכָה זֹעֲמָה יִשְׂרָאֵל׃
מָה אֶקֹּב לֹא קַבֹּה אֵל וּמָה אֶזְעֹם לֹא זָעַם יְהוָה׃
כִּי־מֵרֹאשׁ צֻרִים אֶרְאֶנּוּ וּמִגְּבָעוֹת אֲשׁוּרֶנּוּ הֶן־עָם לְבָדָד יִשְׁכֹּן וּבַגּוֹיִם לֹא יִתְחַשָּׁב׃
מִי מָנָה עֲפַר יַעֲקֹב וּמִסְפָּר אֶת־רֹבַע יִשְׂרָאֵל תָּמֹת נַפְשִׁי מוֹת יְשָׁרִים וּתְהִי אַחֲרִיתִי כָּמֹהוּ׃
וַיֹּאמֶר בָּלָק אֶל־בִּלְעָם מֶה עָשִׂיתָ לִי לָקֹב אֹיְבַי לְקַחְתִּיךָ וְהִנֵּה בֵּרַכְתָּ בָרֵךְ׃
וַיַּעַן וַיֹּאמַר הֲלֹא אֵת אֲשֶׁר יָשִׂים יְהוָה בְּפִי אֹתוֹ אֶשְׁמֹר לְדַבֵּר׃
וַיֹּאמֶר אֵלָיו בָּלָק לך־[לְכָה־] נָּא אִתִּי אֶל־מָקוֹם אַחֵר אֲשֶׁר תִּרְאֶנּוּ מִשָּׁם אֶפֶס קָצֵהוּ תִרְאֶה וְכֻלּוֹ לֹא תִרְאֶה וְקָבְנוֹ־לִי מִשָּׁם׃
וַיִּקָּחֵהוּ שְׂדֵה צֹפִים אֶל־רֹאשׁ הַפִּסְגָּה וַיִּבֶן שִׁבְעָה מִזְבְּחֹת וַיַּעַל פָּר וָאַיִל בַּמִּזְבֵּחַ׃
וַיֹּאמֶר אֶל־בָּלָק הִתְיַצֵּב כֹּה עַל־עֹלָתֶךָ וְאָנֹכִי אִקָּרֶה כֹּה׃
וַיִּקָּר יְהוָה אֶל־בִּלְעָם וַיָּשֶׂם דָּבָר בְּפִיו וַיֹּאמֶר שׁוּב אֶל־בָּלָק וְכֹה תְדַבֵּר׃
וַיָּבֹא אֵלָיו וְהִנּוֹ נִצָּב עַל־עֹלָתוֹ וְשָׂרֵי מוֹאָב אִתּוֹ וַיֹּאמֶר לוֹ בָּלָק מַה־דִּבֶּר יְהוָה׃
וַיִּשָּׂא מְשָׁלוֹ וַיֹּאמַר קוּם בָּלָק וּשֲׁמָע הַאֲזִינָה עָדַי בְּנוֹ צִפֹּר׃
לֹא אִישׁ אֵל וִיכַזֵּב וּבֶן־אָדָם וְיִתְנֶחָם הַהוּא אָמַר וְלֹא יַעֲשֶׂה וְדִבֶּר וְלֹא יְקִימֶנָּה׃
הִנֵּה בָרֵךְ לָקָחְתִּי וּבֵרֵךְ וְלֹא אֲשִׁיבֶנָּה׃
לֹא־הִבִּיט אָוֶן בְּיַעֲקֹב וְלֹא־רָאָה עָמָל בְּיִשְׂרָאֵל יְהוָה אֱלֹהָיו עִמּוֹ וּתְרוּעַת מֶלֶךְ בּוֹ׃
אֵל מוֹצִיאָם מִמִּצְרָיִם כְּתוֹעֲפֹת רְאֵם לוֹ׃
כִּי לֹא־נַחַשׁ בְּיַעֲקֹב וְלֹא־קֶסֶם בְּיִשְׂרָאֵל כָּעֵת יֵאָמֵר לְיַעֲקֹב וּלְיִשְׂרָאֵל מַה־פָּעַל אֵל׃
הֶן־עָם כְּלָבִיא יָקוּם וְכַאֲרִי יִתְנַשָּׂא לֹא יִשְׁכַּב עַד־יֹאכַל טֶרֶף וְדַם־חֲלָלִים יִשְׁתֶּה׃
וַיֹּאמֶר בָּלָק אֶל־בִּלְעָם גַּם־קֹב לֹא תִקֳּבֶנּוּ גַּם־בָּרֵךְ לֹא תְבָרֲכֶנּוּ׃
וַיַּעַן בִּלְעָם וַיֹּאמֶר אֶל־בָּלָק הֲלֹא דִּבַּרְתִּי אֵלֶיךָ לֵאמֹר כֹּל אֲשֶׁר־יְדַבֵּר יְהוָה אֹתוֹ אֶעֱשֶׂה׃
וַיֹּאמֶר בָּלָק אֶל־בִּלְעָם לְכָה־נָּא אֶקָּחֲךָ אֶל־מָקוֹם אַחֵר אוּלַי יִישַׁר בְּעֵינֵי הָאֱלֹהִים וְקַבֹּתוֹ לִי מִשָּׁם׃
וַיִּקַּח בָּלָק אֶת־בִּלְעָם רֹאשׁ הַפְּעוֹר הַנִּשְׁקָף עַל־פְּנֵי הַיְשִׁימֹן׃
וַיֹּאמֶר בִּלְעָם אֶל־בָּלָק בְּנֵה־לִי בָזֶה שִׁבְעָה מִזְבְּחֹת וְהָכֵן לִי בָּזֶה שִׁבְעָה פָרִים וְשִׁבְעָה אֵילִים׃
וַיַּעַשׂ בָּלָק כַּאֲשֶׁר אָמַר בִּלְעָם וַיַּעַל פָּר וָאַיִל בַּמִּזְבֵּחַ׃

Chapter 24

וַיַּרְא בִּלְעָם כִּי טוֹב בְּעֵינֵי יְהוָה לְבָרֵךְ אֶת־יִשְׂרָאֵל וְלֹא־הָלַךְ כְּפַעַם־בְּפַעַם לִקְרַאת נְחָשִׁים וַיָּשֶׁת אֶל־הַמִּדְבָּר פָּנָיו׃
וַיִּשָּׂא בִלְעָם אֶת־עֵינָיו וַיַּרְא אֶת־יִשְׂרָאֵל שֹׁכֵן לִשְׁבָטָיו וַתְּהִי עָלָיו רוּחַ אֱלֹהִים׃
וַיִּשָּׂא מְשָׁלוֹ וַיֹּאמַר נְאֻם בִּלְעָם בְּנוֹ בְעֹר וּנְאֻם הַגֶּבֶר שְׁתֻם הָעָיִן׃
נְאֻם שֹׁמֵעַ אִמְרֵי־אֵל אֲשֶׁר מַחֲזֵה שַׁדַּי יֶחֱזֶה נֹפֵל וּגְלוּי עֵינָיִם׃
מַה־טֹּבוּ אֹהָלֶיךָ יַעֲקֹב מִשְׁכְּנֹתֶיךָ יִשְׂרָאֵל׃
כִּנְחָלִים נִטָּיוּ כְּגַנֹּת עֲלֵי נָהָר כַּאֲהָלִים נָטַע יְהוָה כַּאֲרָזִים עֲלֵי־מָיִם׃
יִזַּל־מַיִם מִדָּלְיָו וְזַרְעוֹ בְּמַיִם רַבִּים וְיָרֹם מֵאֲגַג מַלְכּוֹ וְתִנַּשֵּׂא מַלְכֻתוֹ׃
אֵל מוֹצִיאוֹ מִמִּצְרַיִם כְּתוֹעֲפֹת רְאֵם לוֹ יֹאכַל גּוֹיִם צָרָיו וְעַצְמֹתֵיהֶם יְגָרֵם וְחִצָּיו יִמְחָץ׃
כָּרַע שָׁכַב כַּאֲרִי וּכְלָבִיא מִי יְקִימֶנּוּ מְבָרֲכֶיךָ בָרוּךְ וְאֹרְרֶיךָ אָרוּר׃
וַיִּחַר־אַף בָּלָק אֶל־בִּלְעָם וַיִּסְפֹּק אֶת־כַּפָּיו וַיֹּאמֶר בָּלָק אֶל־בִּלְעָם לָקֹב אֹיְבַי קְרָאתִיךָ וְהִנֵּה בֵּרַכְתָּ בָרֵךְ זֶה שָׁלֹשׁ פְּעָמִים׃
וְעַתָּה בְּרַח־לְךָ אֶל־מְקוֹמֶךָ אָמַרְתִּי כַּבֵּד אֲכַבֶּדְךָ וְהִנֵּה מְנָעֲךָ יְהוָה מִכָּבוֹד׃
וַיֹּאמֶר בִּלְעָם אֶל־בָּלָק הֲלֹא גַּם אֶל־מַלְאָכֶיךָ אֲשֶׁר־שָׁלַחְתָּ אֵלַי דִּבַּרְתִּי לֵאמֹר׃
אִם־יִתֶּן־לִי בָלָק מְלֹא בֵיתוֹ כֶּסֶף וְזָהָב לֹא אוּכַל לַעֲבֹר אֶת־פִּי יְהוָה לַעֲשׂוֹת טוֹבָה אוֹ רָעָה מִלִּבִּי אֲשֶׁר־יְדַבֵּר יְהוָה אֹתוֹ אֲדַבֵּר׃
וְעַתָּה הִנְנִי הוֹלֵךְ לְעַמִּי לְכָה אִיעָצְךָ אֲשֶׁר יַעֲשֶׂה הָעָם הַזֶּה לְעַמְּךָ בְּאַחֲרִית הַיָּמִים׃
וַיִּשָּׂא מְשָׁלוֹ וַיֹּאמַר נְאֻם בִּלְעָם בְּנוֹ בְעֹר וּנְאֻם הַגֶּבֶר שְׁתֻם הָעָיִן׃
נְאֻם שֹׁמֵעַ אִמְרֵי־אֵל וְיֹדֵעַ דַּעַת עֶלְיוֹן מַחֲזֵה שַׁדַּי יֶחֱזֶה נֹפֵל וּגְלוּי עֵינָיִם׃
אֶרְאֶנּוּ וְלֹא עַתָּה אֲשׁוּרֶנּוּ וְלֹא קָרוֹב דָּרַךְ כּוֹכָב מִיַּעֲקֹב וְקָם שֵׁבֶט מִיִּשְׂרָאֵל וּמָחַץ פַּאֲתֵי מוֹאָב וְקַרְקַר כָּל־בְּנֵי־שֵׁת׃
וְהָיָה אֱדוֹם יְרֵשָׁה וְהָיָה יְרֵשָׁה שֵׂעִיר אֹיְבָיו וְיִשְׂרָאֵל עֹשֶׂה חָיִל׃
וְיֵרְדְּ מִיַּעֲקֹב וְהֶאֱבִיד שָׂרִיד מֵעִיר׃
וַיַּרְא אֶת־עֲמָלֵק וַיִּשָּׂא מְשָׁלוֹ וַיֹּאמַר רֵאשִׁית גּוֹיִם עֲמָלֵק וְאַחֲרִיתוֹ עֲדֵי אֹבֵד׃
וַיַּרְא אֶת־הַקֵּינִי וַיִּשָּׂא מְשָׁלוֹ וַיֹּאמַר אֵיתָן מוֹשָׁבֶךָ וְשִׂים בַּסֶּלַע קִנֶּךָ׃
כִּי אִם־יִהְיֶה לְבָעֵר קָיִן עַד־מָה אַשּׁוּר תִּשְׁבֶּךָּ׃
וַיִּשָּׂא מְשָׁלוֹ וַיֹּאמַר אוֹי מִי יִחְיֶה מִשֻּׂמוֹ אֵל׃
וְצִים מִיַּד כִּתִּים וְעִנּוּ אַשּׁוּר וְעִנּוּ־עֵבֶר וְגַם־הוּא עֲדֵי אֹבֵד׃
וַיָּקָם בִּלְעָם וַיֵּלֶךְ וַיָּשָׁב לִמְקֹמוֹ וְגַם־בָּלָק הָלַךְ לְדַרְכּוֹ׃

Chapter 25

וַיֵּשֶׁב יִשְׂרָאֵל בַּשִּׁטִּים וַיָּחֶל הָעָם לִזְנוֹת אֶל־בְּנוֹת מוֹאָב׃
וַתִּקְרֶאןָ לָעָם לְזִבְחֵי אֱלֹהֵיהֶן וַיֹּאכַל הָעָם וַיִּשְׁתַּחֲוּוּ לֵאלֹהֵיהֶן׃
וַיִּצָּמֶד יִשְׂרָאֵל לְבַעַל פְּעוֹר וַיִּחַר־אַף יְהוָה בְּיִשְׂרָאֵל׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה קַח אֶת־כָּל־רָאשֵׁי הָעָם וְהוֹקַע אוֹתָם לַיהוָה נֶגֶד הַשָּׁמֶשׁ וְיָשֹׁב חֲרוֹן אַף־יְהוָה מִיִּשְׂרָאֵל׃
וַיֹּאמֶר מֹשֶׁה אֶל־שֹׁפְטֵי יִשְׂרָאֵל הִרְגוּ אִישׁ אֲנָשָׁיו הַנִּצְמָדִים לְבַעַל פְּעוֹר׃
וְהִנֵּה אִישׁ מִבְּנֵי יִשְׂרָאֵל בָּא וַיַּקְרֵב אֶל־אֶחָיו אֶת־הַמִּדְיָנִית לְעֵינֵי מֹשֶׁה וּלְעֵינֵי כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל וְהֵמָּה בֹכִים פֶּתַח אֹהֶל מוֹעֵד׃
וַיַּרְא פִּינְחָס בֶּן־אֶלְעָזָר בֶּן־אַהֲרֹן הַכֹּהֵן וַיָּקָם מִתּוֹךְ הָעֵדָה וַיִּקַּח רֹמַח בְּיָדוֹ׃
וַיָּבֹא אַחַר אִישׁ־יִשְׂרָאֵל אֶל־הַקֻּבָּה וַיִּדְקֹר אֶת־שְׁנֵיהֶם אֵת אִישׁ יִשְׂרָאֵל וְאֶת־הָאִשָּׁה אֶל־קֳבָתָהּ וַתֵּעָצַר הַמַּגֵּפָה מֵעַל בְּנֵי יִשְׂרָאֵל׃
וַיִּהְיוּ הַמֵּתִים בַּמַּגֵּפָה אַרְבָּעָה וְעֶשְׂרִים אָלֶף׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
פִּינְחָס בֶּן־אֶלְעָזָר בֶּן־אַהֲרֹן הַכֹּהֵן הֵשִׁיב אֶת־חֲמָתִי מֵעַל בְּנֵי־יִשְׂרָאֵל בְּקַנְאוֹ אֶת־קִנְאָתִי בְּתוֹכָם וְלֹא־כִלִּיתִי אֶת־בְּנֵי־יִשְׂרָאֵל בְּקִנְאָתִי׃
לָכֵן אֱמֹר הִנְנִי נֹתֵן לוֹ אֶת־בְּרִיתִי שָׁלוֹם׃
וְהָיְתָה לּוֹ וּלְזַרְעוֹ אַחֲרָיו בְּרִית כְּהֻנַּת עוֹלָם תַּחַת אֲשֶׁר קִנֵּא לֵאלֹהָיו וַיְכַפֵּר עַל־בְּנֵי יִשְׂרָאֵל׃
וְשֵׁם אִישׁ יִשְׂרָאֵל הַמֻּכֶּה אֲשֶׁר הֻכָּה אֶת־הַמִּדְיָנִית זִמְרִי בֶּן־סָלוּא נְשִׂיא בֵית־אָב לַשִּׁמְעֹנִי׃
וְשֵׁם הָאִשָּׁה הַמֻּכָּה הַמִּדְיָנִית כָּזְבִּי בַת־צוּר רֹאשׁ אֻמּוֹת בֵּית־אָב בְּמִדְיָן הוּא׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
צָרוֹר אֶת־הַמִּדְיָנִים וְהִכִּיתֶם אוֹתָם׃
כִּי צֹרְרִים הֵם לָכֶם בְּנִכְלֵיהֶם אֲשֶׁר־נִכְּלוּ לָכֶם עַל־דְּבַר־פְּעוֹר וְעַל־דְּבַר כָּזְבִּי בַת־נְשִׂיא מִדְיָן אֲחֹתָם הַמֻּכָּה בְיוֹם־הַמַּגֵּפָה עַל־דְּבַר־פְּעוֹר׃

Chapter 26

וַיְהִי אַחֲרֵי הַמַּגֵּפָה וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה וְאֶל אֶלְעָזָר בֶּן־אַהֲרֹן הַכֹּהֵן לֵאמֹר׃
שְׂאוּ אֶת־רֹאשׁ כָּל־עֲדַת בְּנֵי־יִשְׂרָאֵל מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה לְבֵית אֲבֹתָם כָּל־יֹצֵא צָבָא בְּיִשְׂרָאֵל׃
וַיְדַבֵּר מֹשֶׁה וְאֶלְעָזָר הַכֹּהֵן אֹתָם בְּעַרְבֹת מוֹאָב עַל־יַרְדֵּן יְרֵחוֹ לֵאמֹר׃
מִבֶּן עֶשְׂרִים שָׁנָה וָמָעְלָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה וּבְנֵי יִשְׂרָאֵל הַיֹּצְאִים מֵאֶרֶץ מִצְרָיִם׃
רְאוּבֵן בְּכוֹר יִשְׂרָאֵל בְּנֵי רְאוּבֵן חֲנוֹךְ מִשְׁפַּחַת הַחֲנֹכִי לְפַלּוּא מִשְׁפַּחַת הַפַּלֻּאִי׃
לְחֶצְרֹן מִשְׁפַּחַת הַחֶצְרוֹנִי לְכַרְמִי מִשְׁפַּחַת הַכַּרְמִי׃
אֵלֶּה מִשְׁפְּחֹת הָרֻאוּבֵנִי וַיִּהְיוּ פְקֻדֵיהֶם שְׁלֹשָׁה וְאַרְבָּעִים אֶלֶף וּשְׁבַע מֵאוֹת וּשְׁלֹשִׁים׃
וּבְנֵי פַלּוּא אֱלִיאָב׃
וּבְנֵי אֱלִיאָב נְמוּאֵל וְדָתָן וַאֲבִירָם הוּא־דָתָן וַאֲבִירָם קרואי [קְרִיאֵי] הָעֵדָה אֲשֶׁר הִצּוּ עַל־מֹשֶׁה וְעַל־אַהֲרֹן בַּעֲדַת־קֹרַח בְּהַצֹּתָם עַל־יְהוָה׃
וַתִּפְתַּח הָאָרֶץ אֶת־פִּיהָ וַתִּבְלַע אֹתָם וְאֶת־קֹרַח בְּמוֹת הָעֵדָה בַּאֲכֹל הָאֵשׁ אֵת חֲמִשִּׁים וּמָאתַיִם אִישׁ וַיִּהְיוּ לְנֵס׃
וּבְנֵי־קֹרַח לֹא־מֵתוּ׃
בְּנֵי שִׁמְעוֹן לְמִשְׁפְּחֹתָם לִנְמוּאֵל מִשְׁפַּחַת הַנְּמוּאֵלִי לְיָמִין מִשְׁפַּחַת הַיָּמִינִי לְיָכִין מִשְׁפַּחַת הַיָּכִינִי׃
לְזֶרַח מִשְׁפַּחַת הַזַּרְחִי לְשָׁאוּל מִשְׁפַּחַת הַשָּׁאוּלִי׃
אֵלֶּה מִשְׁפְּחֹת הַשִּׁמְעֹנִי שְׁנַיִם וְעֶשְׂרִים אֶלֶף וּמָאתָיִם׃
בְּנֵי גָד לְמִשְׁפְּחֹתָם לִצְפוֹן מִשְׁפַּחַת הַצְּפוֹנִי לְחַגִּי מִשְׁפַּחַת הַחַגִּי לְשׁוּנִי מִשְׁפַּחַת הַשּׁוּנִי׃
לְאָזְנִי מִשְׁפַּחַת הָאָזְנִי לְעֵרִי מִשְׁפַּחַת הָעֵרִי׃
לַאֲרוֹד מִשְׁפַּחַת הָאֲרוֹדִי לְאַרְאֵלִי מִשְׁפַּחַת הָאַרְאֵלִי׃
אֵלֶּה מִשְׁפְּחֹת בְּנֵי־גָד לִפְקֻדֵיהֶם אַרְבָּעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
בְּנֵי יְהוּדָה עֵר וְאוֹנָן וַיָּמָת עֵר וְאוֹנָן בְּאֶרֶץ כְּנָעַן׃
וַיִּהְיוּ בְנֵי־יְהוּדָה לְמִשְׁפְּחֹתָם לְשֵׁלָה מִשְׁפַּחַת הַשֵּׁלָנִי לְפֶרֶץ מִשְׁפַּחַת הַפַּרְצִי לְזֶרַח מִשְׁפַּחַת הַזַּרְחִי׃
וַיִּהְיוּ בְנֵי־פֶרֶץ לְחֶצְרֹן מִשְׁפַּחַת הַחֶצְרֹנִי לְחָמוּל מִשְׁפַּחַת הֶחָמוּלִי׃
אֵלֶּה מִשְׁפְּחֹת יְהוּדָה לִפְקֻדֵיהֶם שִׁשָּׁה וְשִׁבְעִים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
בְּנֵי יִשָּׂשכָר לְמִשְׁפְּחֹתָם תּוֹלָע מִשְׁפַּחַת הַתּוֹלָעִי לְפֻוָה מִשְׁפַּחַת הַפּוּנִי׃
לְיָשׁוּב מִשְׁפַּחַת הַיָּשׁוּבִי לְשִׁמְרֹן מִשְׁפַּחַת הַשִּׁמְרֹנִי׃
אֵלֶּה מִשְׁפְּחֹת יִשָּׂשכָר לִפְקֻדֵיהֶם אַרְבָּעָה וְשִׁשִּׁים אֶלֶף וּשְׁלֹשׁ מֵאוֹת׃
בְּנֵי זְבוּלֻן לְמִשְׁפְּחֹתָם לְסֶרֶד מִשְׁפַּחַת הַסַּרְדִּי לְאֵלוֹן מִשְׁפַּחַת הָאֵלֹנִי לְיַחְלְאֵל מִשְׁפַּחַת הַיַּחְלְאֵלִי׃
אֵלֶּה מִשְׁפְּחֹת הַזְּבוּלֹנִי לִפְקֻדֵיהֶם שִׁשִּׁים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
בְּנֵי יוֹסֵף לְמִשְׁפְּחֹתָם מְנַשֶּׁה וְאֶפְרָיִם׃
בְּנֵי מְנַשֶּׁה לְמָכִיר מִשְׁפַּחַת הַמָּכִירִי וּמָכִיר הוֹלִיד אֶת־גִּלְעָד לְגִלְעָד מִשְׁפַּחַת הַגִּלְעָדִי׃
אֵלֶּה בְּנֵי גִלְעָד אִיעֶזֶר מִשְׁפַּחַת הָאִיעֶזְרִי לְחֵלֶק מִשְׁפַּחַת הַחֶלְקִי׃
וְאַשְׂרִיאֵל מִשְׁפַּחַת הָאַשְׂרִאֵלִי וְשֶׁכֶם מִשְׁפַּחַת הַשִּׁכְמִי׃
וּשְׁמִידָע מִשְׁפַּחַת הַשְּׁמִידָעִי וְחֵפֶר מִשְׁפַּחַת הַחֶפְרִי׃
וּצְלָפְחָד בֶּן־חֵפֶר לֹא־הָיוּ לוֹ בָּנִים כִּי אִם־בָּנוֹת וְשֵׁם בְּנוֹת צְלָפְחָד מַחְלָה וְנֹעָה חָגְלָה מִלְכָּה וְתִרְצָה׃
אֵלֶּה מִשְׁפְּחֹת מְנַשֶּׁה וּפְקֻדֵיהֶם שְׁנַיִם וַחֲמִשִּׁים אֶלֶף וּשְׁבַע מֵאוֹת׃
אֵלֶּה בְנֵי־אֶפְרַיִם לְמִשְׁפְּחֹתָם לְשׁוּתֶלַח מִשְׁפַּחַת הַשֻּׁתַלְחִי לְבֶכֶר מִשְׁפַּחַת הַבַּכְרִי לְתַחַן מִשְׁפַּחַת הַתַּחֲנִי׃
וְאֵלֶּה בְּנֵי שׁוּתָלַח לְעֵרָן מִשְׁפַּחַת הָעֵרָנִי׃
אֵלֶּה מִשְׁפְּחֹת בְּנֵי־אֶפְרַיִם לִפְקֻדֵיהֶם שְׁנַיִם וּשְׁלֹשִׁים אֶלֶף וַחֲמֵשׁ מֵאוֹת אֵלֶּה בְנֵי־יוֹסֵף לְמִשְׁפְּחֹתָם׃
בְּנֵי בִנְיָמִן לְמִשְׁפְּחֹתָם לְבֶלַע מִשְׁפַּחַת הַבַּלְעִי לְאַשְׁבֵּל מִשְׁפַּחַת הָאַשְׁבֵּלִי לַאֲחִירָם מִשְׁפַּחַת הָאֲחִירָמִי׃
לִשְׁפוּפָם מִשְׁפַּחַת הַשּׁוּפָמִי לְחוּפָם מִשְׁפַּחַת הַחוּפָמִי׃
וַיִּהְיוּ בְנֵי־בֶלַע אַרְדְּ וְנַעֲמָן מִשְׁפַּחַת הָאַרְדִּי לְנַעֲמָן מִשְׁפַּחַת הַנַּעֲמִי׃
אֵלֶּה בְנֵי־בִנְיָמִן לְמִשְׁפְּחֹתָם וּפְקֻדֵיהֶם חֲמִשָּׁה וְאַרְבָּעִים אֶלֶף וְשֵׁשׁ מֵאוֹת׃
אֵלֶּה בְנֵי־דָן לְמִשְׁפְּחֹתָם לְשׁוּחָם מִשְׁפַּחַת הַשּׁוּחָמִי אֵלֶּה מִשְׁפְּחֹת דָּן לְמִשְׁפְּחֹתָם׃
כָּל־מִשְׁפְּחֹת הַשּׁוּחָמִי לִפְקֻדֵיהֶם אַרְבָּעָה וְשִׁשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
בְּנֵי אָשֵׁר לְמִשְׁפְּחֹתָם לְיִמְנָה מִשְׁפַּחַת הַיִּמְנָה לְיִשְׁוִי מִשְׁפַּחַת הַיִּשְׁוִי לִבְרִיעָה מִשְׁפַּחַת הַבְּרִיעִי׃
לִבְנֵי בְרִיעָה לְחֶבֶר מִשְׁפַּחַת הַחֶבְרִי לְמַלְכִּיאֵל מִשְׁפַּחַת הַמַּלְכִּיאֵלִי׃
וְשֵׁם בַּת־אָשֵׁר שָׂרַח׃
אֵלֶּה מִשְׁפְּחֹת בְּנֵי־אָשֵׁר לִפְקֻדֵיהֶם שְׁלֹשָׁה וַחֲמִשִּׁים אֶלֶף וְאַרְבַּע מֵאוֹת׃
בְּנֵי נַפְתָּלִי לְמִשְׁפְּחֹתָם לְיַחְצְאֵל מִשְׁפַּחַת הַיַּחְצְאֵלִי לְגוּנִי מִשְׁפַּחַת הַגּוּנִי׃
לְיֵצֶר מִשְׁפַּחַת הַיִּצְרִי לְשִׁלֵּם מִשְׁפַּחַת הַשִּׁלֵּמִי׃
אֵלֶּה מִשְׁפְּחֹת נַפְתָּלִי לְמִשְׁפְּחֹתָם וּפְקֻדֵיהֶם חֲמִשָּׁה וְאַרְבָּעִים אֶלֶף וְאַרְבַּע מֵאוֹת׃
אֵלֶּה פְּקוּדֵי בְּנֵי יִשְׂרָאֵל שֵׁשׁ־מֵאוֹת אֶלֶף וָאָלֶף שְׁבַע מֵאוֹת וּשְׁלֹשִׁים׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
לָאֵלֶּה תֵּחָלֵק הָאָרֶץ בְּנַחֲלָה בְּמִסְפַּר שֵׁמוֹת׃
לָרַב תַּרְבֶּה נַחֲלָתוֹ וְלַמְעַט תַּמְעִיט נַחֲלָתוֹ אִישׁ לְפִי פְקֻדָיו יֻתַּן נַחֲלָתוֹ׃
אַךְ־בְּגוֹרָל יֵחָלֵק אֶת־הָאָרֶץ לִשְׁמוֹת מַטּוֹת־אֲבֹתָם יִנְחָלוּ׃
עַל־פִּי הַגּוֹרָל תֵּחָלֵק נַחֲלָתוֹ בֵּין רַב לִמְעָט׃
וְאֵלֶּה פְקוּדֵי הַלֵּוִי לְמִשְׁפְּחֹתָם לְגֵרְשׁוֹן מִשְׁפַּחַת הַגֵּרְשֻׁנִּי לִקְהָת מִשְׁפַּחַת הַקְּהָתִי לִמְרָרִי מִשְׁפַּחַת הַמְּרָרִי׃
אֵלֶּה מִשְׁפְּחֹת לֵוִי מִשְׁפַּחַת הַלִּבְנִי מִשְׁפַּחַת הַחֶבְרֹנִי מִשְׁפַּחַת הַמַּחְלִי מִשְׁפַּחַת הַמּוּשִׁי מִשְׁפַּחַת הַקָּרְחִי וּקְהָת הוֹלִד אֶת־עַמְרָם׃
וְשֵׁם אֵשֶׁת עַמְרָם יוֹכֶבֶד בַּת־לֵוִי אֲשֶׁר יָלְדָה אֹתָהּ לְלֵוִי בְּמִצְרָיִם וַתֵּלֶד לְעַמְרָם אֶת־אַהֲרֹן וְאֶת־מֹשֶׁה וְאֵת מִרְיָם אֲחֹתָם׃
וַיִּוָּלֵד לְאַהֲרֹן אֶת־נָדָב וְאֶת־אֲבִיהוּא אֶת־אֶלְעָזָר וְאֶת־אִיתָמָר׃
וַיָּמָת נָדָב וַאֲבִיהוּא בְּהַקְרִיבָם אֵשׁ־זָרָה לִפְנֵי יְהוָה׃
וַיִּהְיוּ פְקֻדֵיהֶם שְׁלֹשָׁה וְעֶשְׂרִים אֶלֶף כָּל־זָכָר מִבֶּן־חֹדֶשׁ וָמָעְלָה כִּי לֹא הָתְפָּקְדוּ בְּתוֹךְ בְּנֵי יִשְׂרָאֵל כִּי לֹא־נִתַּן לָהֶם נַחֲלָה בְּתוֹךְ בְּנֵי יִשְׂרָאֵל׃
אֵלֶּה פְּקוּדֵי מֹשֶׁה וְאֶלְעָזָר הַכֹּהֵן אֲשֶׁר פָּקְדוּ אֶת־בְּנֵי יִשְׂרָאֵל בְּעַרְבֹת מוֹאָב עַל יַרְדֵּן יְרֵחוֹ׃
וּבְאֵלֶּה לֹא־הָיָה אִישׁ מִפְּקוּדֵי מֹשֶׁה וְאַהֲרֹן הַכֹּהֵן אֲשֶׁר פָּקְדוּ אֶת־בְּנֵי יִשְׂרָאֵל בְּמִדְבַּר סִינָי׃
כִּי־אָמַר יְהוָה לָהֶם מוֹת יָמֻתוּ בַּמִּדְבָּר וְלֹא־נוֹתַר מֵהֶם אִישׁ כִּי אִם־כָּלֵב בֶּן־יְפֻנֶּה וִיהוֹשֻׁעַ בִּן־נוּן׃

Chapter 27

וַתִּקְרַבְנָה בְּנוֹת צְלָפְחָד בֶּן־חֵפֶר בֶּן־גִּלְעָד בֶּן־מָכִיר בֶּן־מְנַשֶּׁה לְמִשְׁפְּחֹת מְנַשֶּׁה בֶן־יוֹסֵף וְאֵלֶּה שְׁמוֹת בְּנֹתָיו מַחְלָה נֹעָה וְחָגְלָה וּמִלְכָּה וְתִרְצָה׃
וַתַּעֲמֹדְנָה לִפְנֵי מֹשֶׁה וְלִפְנֵי אֶלְעָזָר הַכֹּהֵן וְלִפְנֵי הַנְּשִׂיאִם וְכָל־הָעֵדָה פֶּתַח אֹהֶל־מוֹעֵד לֵאמֹר׃
אָבִינוּ מֵת בַּמִּדְבָּר וְהוּא לֹא־הָיָה בְּתוֹךְ הָעֵדָה הַנּוֹעָדִים עַל־יְהוָה בַּעֲדַת־קֹרַח כִּי־בְחֶטְאוֹ מֵת וּבָנִים לֹא־הָיוּ לוֹ׃
לָמָּה יִגָּרַע שֵׁם־אָבִינוּ מִתּוֹךְ מִשְׁפַּחְתּוֹ כִּי אֵין לוֹ בֵּן תְּנָה־לָּנוּ אֲחֻזָּה בְּתוֹךְ אֲחֵי אָבִינוּ׃
וַיַּקְרֵב מֹשֶׁה אֶת־מִשְׁפָּטָן לִפְנֵי יְהוָה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
כֵּן בְּנוֹת צְלָפְחָד דֹּבְרֹת נָתֹן תִּתֵּן לָהֶם אֲחֻזַּת נַחֲלָה בְּתוֹךְ אֲחֵי אֲבִיהֶם וְהַעֲבַרְתָּ אֶת־נַחֲלַת אֲבִיהֶן לָהֶן׃
וְאֶל־בְּנֵי יִשְׂרָאֵל תְּדַבֵּר לֵאמֹר אִישׁ כִּי־יָמוּת וּבֵן אֵין לוֹ וְהַעֲבַרְתֶּם אֶת־נַחֲלָתוֹ לְבִתּוֹ׃
וְאִם־אֵין לוֹ בַּת וּנְתַתֶּם אֶת־נַחֲלָתוֹ לְאֶחָיו׃
וְאִם־אֵין לוֹ אַחִים וּנְתַתֶּם אֶת־נַחֲלָתוֹ לַאֲחֵי אָבִיו׃
וְאִם־אֵין אַחִים לְאָבִיו וּנְתַתֶּם אֶת־נַחֲלָתוֹ לִשְׁאֵרוֹ הַקָּרֹב אֵלָיו מִמִּשְׁפַּחְתּוֹ וְיָרַשׁ אֹתָהּ וְהָיְתָה לִבְנֵי יִשְׂרָאֵל לְחֻקַּת מִשְׁפָּט כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה עֲלֵה אֶל־הַר הָעֲבָרִים הַזֶּה וּרְאֵה אֶת־הָאָרֶץ אֲשֶׁר נָתַתִּי לִבְנֵי יִשְׂרָאֵל׃
וְרָאִיתָה אֹתָהּ וְנֶאֱסַפְתָּ אֶל־עַמֶּיךָ גַּם־אָתָּה כַּאֲשֶׁר נֶאֱסַף אַהֲרֹן אָחִיךָ׃
כַּאֲשֶׁר מְרִיתֶם פִּי בְּמִדְבַּר־צִן בִּמְרִיבַת הָעֵדָה לְהַקְדִּישֵׁנִי בַמַּיִם לְעֵינֵיהֶם הֵם מֵי־מְרִיבַת קָדֵשׁ מִדְבַּר־צִן׃
וַיְדַבֵּר מֹשֶׁה אֶל־יְהוָה לֵאמֹר׃
יִפְקֹד יְהוָה אֱלֹהֵי הָרוּחֹת לְכָל־בָּשָׂר אִישׁ עַל־הָעֵדָה׃
אֲשֶׁר־יֵצֵא לִפְנֵיהֶם וַאֲשֶׁר יָבֹא לִפְנֵיהֶם וַאֲשֶׁר יוֹצִיאֵם וַאֲשֶׁר יְבִיאֵם וְלֹא תִהְיֶה עֲדַת יְהוָה כַּצֹּאן אֲשֶׁר אֵין־לָהֶם רֹעֶה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה קַח־לְךָ אֶת־יְהוֹשֻׁעַ בִּן־נוּן אִישׁ אֲשֶׁר־רוּחַ בּוֹ וְסָמַכְתָּ אֶת־יָדְךָ עָלָיו׃
וְהַעֲמַדְתָּ אֹתוֹ לִפְנֵי אֶלְעָזָר הַכֹּהֵן וְלִפְנֵי כָּל־הָעֵדָה וְצִוִּיתָה אֹתוֹ לְעֵינֵיהֶם׃
וְנָתַתָּה מֵהוֹדְךָ עָלָיו לְמַעַן יִשְׁמְעוּ כָּל־עֲדַת בְּנֵי יִשְׂרָאֵל׃
וְלִפְנֵי אֶלְעָזָר הַכֹּהֵן יַעֲמֹד וְשָׁאַל לוֹ בְּמִשְׁפַּט הָאוּרִים לִפְנֵי יְהוָה עַל־פִּיו יֵצְאוּ וְעַל־פִּיו יָבֹאוּ הוּא וְכָל־בְּנֵי־יִשְׂרָאֵל אִתּוֹ וְכָל־הָעֵדָה׃
וַיַּעַשׂ מֹשֶׁה כַּאֲשֶׁר צִוָּה יְהוָה אֹתוֹ וַיִּקַּח אֶת־יְהוֹשֻׁעַ וַיַּעֲמִדֵהוּ לִפְנֵי אֶלְעָזָר הַכֹּהֵן וְלִפְנֵי כָּל־הָעֵדָה׃
וַיִּסְמֹךְ אֶת־יָדָיו עָלָיו וַיְצַוֵּהוּ כַּאֲשֶׁר דִּבֶּר יְהוָה בְּיַד־מֹשֶׁה׃

Chapter 28

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
צַו אֶת־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם אֶת־קָרְבָּנִי לַחְמִי לְאִשַּׁי רֵיחַ נִיחֹחִי תִּשְׁמְרוּ לְהַקְרִיב לִי בְּמוֹעֲדוֹ׃
וְאָמַרְתָּ לָהֶם זֶה הָאִשֶּׁה אֲשֶׁר תַּקְרִיבוּ לַיהוָה כְּבָשִׂים בְּנֵי־שָׁנָה תְמִימִם שְׁנַיִם לַיּוֹם עֹלָה תָמִיד׃
אֶת־הַכֶּבֶשׂ אֶחָד תַּעֲשֶׂה בַבֹּקֶר וְאֵת הַכֶּבֶשׂ הַשֵּׁנִי תַּעֲשֶׂה בֵּין הָעַרְבָּיִם׃
וַעֲשִׂירִית הָאֵיפָה סֹלֶת לְמִנְחָה בְּלוּלָה בְּשֶׁמֶן כָּתִית רְבִיעִת הַהִין׃
עֹלַת תָּמִיד הָעֲשֻׂיָה בְּהַר סִינַי לְרֵיחַ נִיחֹחַ אִשֶּׁה לַיהוָה׃
וְנִסְכּוֹ רְבִיעִת הַהִין לַכֶּבֶשׂ הָאֶחָד בַּקֹּדֶשׁ הַסֵּךְ נֶסֶךְ שֵׁכָר לַיהוָה׃
וְאֵת הַכֶּבֶשׂ הַשֵּׁנִי תַּעֲשֶׂה בֵּין הָעַרְבָּיִם כְּמִנְחַת הַבֹּקֶר וּכְנִסְכּוֹ תַּעֲשֶׂה אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה׃
וּבְיוֹם הַשַּׁבָּת שְׁנֵי־כְבָשִׂים בְּנֵי־שָׁנָה תְּמִימִם וּשְׁנֵי עֶשְׂרֹנִים סֹלֶת מִנְחָה בְּלוּלָה בַשֶּׁמֶן וְנִסְכּוֹ׃
עֹלַת שַׁבַּת בְּשַׁבַּתּוֹ עַל־עֹלַת הַתָּמִיד וְנִסְכָּהּ׃
וּבְרָאשֵׁי חָדְשֵׁיכֶם תַּקְרִיבוּ עֹלָה לַיהוָה פָּרִים בְּנֵי־בָקָר שְׁנַיִם וְאַיִל אֶחָד כְּבָשִׂים בְּנֵי־שָׁנָה שִׁבְעָה תְּמִימִם׃
וּשְׁלֹשָׁה עֶשְׂרֹנִים סֹלֶת מִנְחָה בְּלוּלָה בַשֶּׁמֶן לַפָּר הָאֶחָד וּשְׁנֵי עֶשְׂרֹנִים סֹלֶת מִנְחָה בְּלוּלָה בַשֶּׁמֶן לָאַיִל הָאֶחָד׃
וְעִשָּׂרֹן עִשָּׂרוֹן סֹלֶת מִנְחָה בְּלוּלָה בַשֶּׁמֶן לַכֶּבֶשׂ הָאֶחָד עֹלָה רֵיחַ נִיחֹחַ אִשֶּׁה לַיהוָה׃
וְנִסְכֵּיהֶם חֲצִי הַהִין יִהְיֶה לַפָּר וּשְׁלִישִׁת הַהִין לָאַיִל וּרְבִיעִת הַהִין לַכֶּבֶשׂ יָיִן זֹאת עֹלַת חֹדֶשׁ בְּחָדְשׁוֹ לְחָדְשֵׁי הַשָּׁנָה׃
וּשְׂעִיר עִזִּים אֶחָד לְחַטָּאת לַיהוָה עַל־עֹלַת הַתָּמִיד יֵעָשֶׂה וְנִסְכּוֹ׃
וּבַחֹדֶשׁ הָרִאשׁוֹן בְּאַרְבָּעָה עָשָׂר יוֹם לַחֹדֶשׁ פֶּסַח לַיהוָה׃
וּבַחֲמִשָּׁה עָשָׂר יוֹם לַחֹדֶשׁ הַזֶּה חָג שִׁבְעַת יָמִים מַצּוֹת יֵאָכֵל׃
בַּיּוֹם הָרִאשׁוֹן מִקְרָא־קֹדֶשׁ כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
וְהִקְרַבְתֶּם אִשֶּׁה עֹלָה לַיהוָה פָּרִים בְּנֵי־בָקָר שְׁנַיִם וְאַיִל אֶחָד וְשִׁבְעָה כְבָשִׂים בְּנֵי שָׁנָה תְּמִימִם יִהְיוּ לָכֶם׃
וּמִנְחָתָם סֹלֶת בְּלוּלָה בַשָּׁמֶן שְׁלֹשָׁה עֶשְׂרֹנִים לַפָּר וּשְׁנֵי עֶשְׂרֹנִים לָאַיִל תַּעֲשׂוּ׃
עִשָּׂרוֹן עִשָּׂרוֹן תַּעֲשֶׂה לַכֶּבֶשׂ הָאֶחָד לְשִׁבְעַת הַכְּבָשִׂים׃
וּשְׂעִיר חַטָּאת אֶחָד לְכַפֵּר עֲלֵיכֶם׃
מִלְּבַד עֹלַת הַבֹּקֶר אֲשֶׁר לְעֹלַת הַתָּמִיד תַּעֲשׂוּ אֶת־אֵלֶּה׃
כָּאֵלֶּה תַּעֲשׂוּ לַיּוֹם שִׁבְעַת יָמִים לֶחֶם אִשֵּׁה רֵיחַ־נִיחֹחַ לַיהוָה עַל־עוֹלַת הַתָּמִיד יֵעָשֶׂה וְנִסְכּוֹ׃
וּבַיּוֹם הַשְּׁבִיעִי מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
וּבְיוֹם הַבִּכּוּרִים בְּהַקְרִיבְכֶם מִנְחָה חֲדָשָׁה לַיהוָה בְּשָׁבֻעֹתֵיכֶם מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
וְהִקְרַבְתֶּם עוֹלָה לְרֵיחַ נִיחֹחַ לַיהוָה פָּרִים בְּנֵי־בָקָר שְׁנַיִם אַיִל אֶחָד שִׁבְעָה כְבָשִׂים בְּנֵי שָׁנָה׃
וּמִנְחָתָם סֹלֶת בְּלוּלָה בַשָּׁמֶן שְׁלֹשָׁה עֶשְׂרֹנִים לַפָּר הָאֶחָד שְׁנֵי עֶשְׂרֹנִים לָאַיִל הָאֶחָד׃
עִשָּׂרוֹן עִשָּׂרוֹן לַכֶּבֶשׂ הָאֶחָד לְשִׁבְעַת הַכְּבָשִׂים׃
שְׂעִיר עִזִּים אֶחָד לְכַפֵּר עֲלֵיכֶם׃
מִלְּבַד עֹלַת הַתָּמִיד וּמִנְחָתוֹ תַּעֲשׂוּ תְּמִימִם יִהְיוּ־לָכֶם וְנִסְכֵּיהֶם׃

Chapter 29

וּבַחֹדֶשׁ הַשְּׁבִיעִי בְּאֶחָד לַחֹדֶשׁ מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ יוֹם תְּרוּעָה יִהְיֶה לָכֶם׃
וַעֲשִׂיתֶם עֹלָה לְרֵיחַ נִיחֹחַ לַיהוָה פַּר בֶּן־בָּקָר אֶחָד אַיִל אֶחָד כְּבָשִׂים בְּנֵי־שָׁנָה שִׁבְעָה תְּמִימִם׃
וּמִנְחָתָם סֹלֶת בְּלוּלָה בַשָּׁמֶן שְׁלֹשָׁה עֶשְׂרֹנִים לַפָּר שְׁנֵי עֶשְׂרֹנִים לָאָיִל׃
וְעִשָּׂרוֹן אֶחָד לַכֶּבֶשׂ הָאֶחָד לְשִׁבְעַת הַכְּבָשִׂים׃
וּשְׂעִיר־עִזִּים אֶחָד חַטָּאת לְכַפֵּר עֲלֵיכֶם׃
מִלְּבַד עֹלַת הַחֹדֶשׁ וּמִנְחָתָהּ וְעֹלַת הַתָּמִיד וּמִנְחָתָהּ וְנִסְכֵּיהֶם כְּמִשְׁפָּטָם לְרֵיחַ נִיחֹחַ אִשֶּׁה לַיהוָה׃
וּבֶעָשׂוֹר לַחֹדֶשׁ הַשְּׁבִיעִי הַזֶּה מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם וְעִנִּיתֶם אֶת־נַפְשֹׁתֵיכֶם כָּל־מְלָאכָה לֹא תַעֲשׂוּ׃
וְהִקְרַבְתֶּם עֹלָה לַיהוָה רֵיחַ נִיחֹחַ פַּר בֶּן־בָּקָר אֶחָד אַיִל אֶחָד כְּבָשִׂים בְּנֵי־שָׁנָה שִׁבְעָה תְּמִימִם יִהְיוּ לָכֶם׃
וּמִנְחָתָם סֹלֶת בְּלוּלָה בַשָּׁמֶן שְׁלֹשָׁה עֶשְׂרֹנִים לַפָּר שְׁנֵי עֶשְׂרֹנִים לָאַיִל הָאֶחָד׃
עִשָּׂרוֹן עִשָּׂרוֹן לַכֶּבֶשׂ הָאֶחָד לְשִׁבְעַת הַכְּבָשִׂים׃
שְׂעִיר־עִזִּים אֶחָד חַטָּאת מִלְּבַד חַטַּאת הַכִּפֻּרִים וְעֹלַת הַתָּמִיד וּמִנְחָתָהּ וְנִסְכֵּיהֶם׃
וּבַחֲמִשָּׁה עָשָׂר יוֹם לַחֹדֶשׁ הַשְּׁבִיעִי מִקְרָא־קֹדֶשׁ יִהְיֶה לָכֶם כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ וְחַגֹּתֶם חַג לַיהוָה שִׁבְעַת יָמִים׃
וְהִקְרַבְתֶּם עֹלָה אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה פָּרִים בְּנֵי־בָקָר שְׁלֹשָׁה עָשָׂר אֵילִם שְׁנָיִם כְּבָשִׂים בְּנֵי־שָׁנָה אַרְבָּעָה עָשָׂר תְּמִימִם יִהְיוּ׃
וּמִנְחָתָם סֹלֶת בְּלוּלָה בַשָּׁמֶן שְׁלֹשָׁה עֶשְׂרֹנִים לַפָּר הָאֶחָד לִשְׁלֹשָׁה עָשָׂר פָּרִים שְׁנֵי עֶשְׂרֹנִים לָאַיִל הָאֶחָד לִשְׁנֵי הָאֵילִם׃
וְעִשָּׂרוֹן עִשָּׂרוֹן לַכֶּבֶשׂ הָאֶחָד לְאַרְבָּעָה עָשָׂר כְּבָשִׂים׃
וּשְׂעִיר־עִזִּים אֶחָד חַטָּאת מִלְּבַד עֹלַת הַתָּמִיד מִנְחָתָהּ וְנִסְכָּהּ׃
וּבַיּוֹם הַשֵּׁנִי פָּרִים בְּנֵי־בָקָר שְׁנֵים עָשָׂר אֵילִם שְׁנָיִם כְּבָשִׂים בְּנֵי־שָׁנָה אַרְבָּעָה עָשָׂר תְּמִימִם׃
וּמִנְחָתָם וְנִסְכֵּיהֶם לַפָּרִים לָאֵילִם וְלַכְּבָשִׂים בְּמִסְפָּרָם כַּמִּשְׁפָּט׃
וּשְׂעִיר־עִזִּים אֶחָד חַטָּאת מִלְּבַד עֹלַת הַתָּמִיד וּמִנְחָתָהּ וְנִסְכֵּיהֶם׃
וּבַיּוֹם הַשְּׁלִישִׁי פָּרִים עַשְׁתֵּי־עָשָׂר אֵילִם שְׁנָיִם כְּבָשִׂים בְּנֵי־שָׁנָה אַרְבָּעָה עָשָׂר תְּמִימִם׃
וּמִנְחָתָם וְנִסְכֵּיהֶם לַפָּרִים לָאֵילִם וְלַכְּבָשִׂים בְּמִסְפָּרָם כַּמִּשְׁפָּט׃
וּשְׂעִיר חַטָּאת אֶחָד מִלְּבַד עֹלַת הַתָּמִיד וּמִנְחָתָהּ וְנִסְכָּהּ׃
וּבַיּוֹם הָרְבִיעִי פָּרִים עֲשָׂרָה אֵילִם שְׁנָיִם כְּבָשִׂים בְּנֵי־שָׁנָה אַרְבָּעָה עָשָׂר תְּמִימִם׃
מִנְחָתָם וְנִסְכֵּיהֶם לַפָּרִים לָאֵילִם וְלַכְּבָשִׂים בְּמִסְפָּרָם כַּמִּשְׁפָּט׃
וּשְׂעִיר־עִזִּים אֶחָד חַטָּאת מִלְּבַד עֹלַת הַתָּמִיד מִנְחָתָהּ וְנִסְכָּהּ׃
וּבַיּוֹם הַחֲמִישִׁי פָּרִים תִּשְׁעָה אֵילִם שְׁנָיִם כְּבָשִׂים בְּנֵי־שָׁנָה אַרְבָּעָה עָשָׂר תְּמִימִם׃
וּמִנְחָתָם וְנִסְכֵּיהֶם לַפָּרִים לָאֵילִם וְלַכְּבָשִׂים בְּמִסְפָּרָם כַּמִּשְׁפָּט׃
וּשְׂעִיר חַטָּאת אֶחָד מִלְּבַד עֹלַת הַתָּמִיד וּמִנְחָתָהּ וְנִסְכָּהּ׃
וּבַיּוֹם הַשִּׁשִּׁי פָּרִים שְׁמֹנָה אֵילִם שְׁנָיִם כְּבָשִׂים בְּנֵי־שָׁנָה אַרְבָּעָה עָשָׂר תְּמִימִם׃
וּמִנְחָתָם וְנִסְכֵּיהֶם לַפָּרִים לָאֵילִם וְלַכְּבָשִׂים בְּמִסְפָּרָם כַּמִּשְׁפָּט׃
וּשְׂעִיר חַטָּאת אֶחָד מִלְּבַד עֹלַת הַתָּמִיד מִנְחָתָהּ וּנְסָכֶיהָ׃
וּבַיּוֹם הַשְּׁבִיעִי פָּרִים שִׁבְעָה אֵילִם שְׁנָיִם כְּבָשִׂים בְּנֵי־שָׁנָה אַרְבָּעָה עָשָׂר תְּמִימִם׃
וּמִנְחָתָם וְנִסְכֵּהֶם לַפָּרִים לָאֵילִם וְלַכְּבָשִׂים בְּמִסְפָּרָם כְּמִשְׁפָּטָם׃
וּשְׂעִיר חַטָּאת אֶחָד מִלְּבַד עֹלַת הַתָּמִיד מִנְחָתָהּ וְנִסְכָּהּ׃
בַּיּוֹם הַשְּׁמִינִי עֲצֶרֶת תִּהְיֶה לָכֶם כָּל־מְלֶאכֶת עֲבֹדָה לֹא תַעֲשׂוּ׃
וְהִקְרַבְתֶּם עֹלָה אִשֵּׁה רֵיחַ נִיחֹחַ לַיהוָה פַּר אֶחָד אַיִל אֶחָד כְּבָשִׂים בְּנֵי־שָׁנָה שִׁבְעָה תְּמִימִם׃
מִנְחָתָם וְנִסְכֵּיהֶם לַפָּר לָאַיִל וְלַכְּבָשִׂים בְּמִסְפָּרָם כַּמִּשְׁפָּט׃
וּשְׂעִיר חַטָּאת אֶחָד מִלְּבַד עֹלַת הַתָּמִיד וּמִנְחָתָהּ וְנִסְכָּהּ׃
אֵלֶּה תַּעֲשׂוּ לַיהוָה בְּמוֹעֲדֵיכֶם לְבַד מִנִּדְרֵיכֶם וְנִדְבֹתֵיכֶם לְעֹלֹתֵיכֶם וּלְמִנְחֹתֵיכֶם וּלְנִסְכֵּיכֶם וּלְשַׁלְמֵיכֶם׃

Chapter 30

וַיֹּאמֶר מֹשֶׁה אֶל־בְּנֵי יִשְׂרָאֵל כְּכֹל אֲשֶׁר־צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיְדַבֵּר מֹשֶׁה אֶל־רָאשֵׁי הַמַּטּוֹת לִבְנֵי יִשְׂרָאֵל לֵאמֹר זֶה הַדָּבָר אֲשֶׁר צִוָּה יְהוָה׃
אִישׁ כִּי־יִדֹּר נֶדֶר לַיהוָה אוֹ־הִשָּׁבַע שְׁבֻעָה לֶאְסֹר אִסָּר עַל־נַפְשׁוֹ לֹא יַחֵל דְּבָרוֹ כְּכָל־הַיֹּצֵא מִפִּיו יַעֲשֶׂה׃
וְאִשָּׁה כִּי־תִדֹּר נֶדֶר לַיהוָה וְאָסְרָה אִסָּר בְּבֵית אָבִיהָ בִּנְעֻרֶיהָ׃
וְשָׁמַע אָבִיהָ אֶת־נִדְרָהּ וֶאֱסָרָהּ אֲשֶׁר אָסְרָה עַל־נַפְשָׁהּ וְהֶחֱרִישׁ לָהּ אָבִיהָ וְקָמוּ כָּל־נְדָרֶיהָ וְכָל־אִסָּר אֲשֶׁר־אָסְרָה עַל־נַפְשָׁהּ יָקוּם׃
וְאִם־הֵנִיא אָבִיהָ אֹתָהּ בְּיוֹם שָׁמְעוֹ כָּל־נְדָרֶיהָ וֶאֱסָרֶיהָ אֲשֶׁר־אָסְרָה עַל־נַפְשָׁהּ לֹא יָקוּם וַיהוָה יִסְלַח־לָהּ כִּי־הֵנִיא אָבִיהָ אֹתָהּ׃
וְאִם־הָיוֹ תִהְיֶה לְאִישׁ וּנְדָרֶיהָ עָלֶיהָ אוֹ מִבְטָא שְׂפָתֶיהָ אֲשֶׁר אָסְרָה עַל־נַפְשָׁהּ׃
וְשָׁמַע אִישָׁהּ בְּיוֹם שָׁמְעוֹ וְהֶחֱרִישׁ לָהּ וְקָמוּ נְדָרֶיהָ וֶאֱסָרֶהָ אֲשֶׁר־אָסְרָה עַל־נַפְשָׁהּ יָקֻמוּ׃
וְאִם בְּיוֹם שְׁמֹעַ אִישָׁהּ יָנִיא אוֹתָהּ וְהֵפֵר אֶת־נִדְרָהּ אֲשֶׁר עָלֶיהָ וְאֵת מִבְטָא שְׂפָתֶיהָ אֲשֶׁר אָסְרָה עַל־נַפְשָׁהּ וַיהוָה יִסְלַח־לָהּ׃
וְנֵדֶר אַלְמָנָה וּגְרוּשָׁה כֹּל אֲשֶׁר־אָסְרָה עַל־נַפְשָׁהּ יָקוּם עָלֶיהָ׃
וְאִם־בֵּית אִישָׁהּ נָדָרָה אוֹ־אָסְרָה אִסָּר עַל־נַפְשָׁהּ בִּשְׁבֻעָה׃
וְשָׁמַע אִישָׁהּ וְהֶחֱרִשׁ לָהּ לֹא הֵנִיא אֹתָהּ וְקָמוּ כָּל־נְדָרֶיהָ וְכָל־אִסָּר אֲשֶׁר־אָסְרָה עַל־נַפְשָׁהּ יָקוּם׃
וְאִם־הָפֵר יָפֵר אֹתָם אִישָׁהּ בְּיוֹם שָׁמְעוֹ כָּל־מוֹצָא שְׂפָתֶיהָ לִנְדָרֶיהָ וּלְאִסַּר נַפְשָׁהּ לֹא יָקוּם אִישָׁהּ הֲפֵרָם וַיהוָה יִסְלַח־לָהּ׃
כָּל־נֵדֶר וְכָל־שְׁבֻעַת אִסָּר לְעַנֹּת נָפֶשׁ אִישָׁהּ יְקִימֶנּוּ וְאִישָׁהּ יְפֵרֶנּוּ׃
וְאִם־הַחֲרֵשׁ יַחֲרִישׁ לָהּ אִישָׁהּ מִיּוֹם אֶל־יוֹם וְהֵקִים אֶת־כָּל־נְדָרֶיהָ אוֹ אֶת־כָּל־אֱסָרֶיהָ אֲשֶׁר עָלֶיהָ הֵקִים אֹתָם כִּי־הֶחֱרִשׁ לָהּ בְּיוֹם שָׁמְעוֹ׃
וְאִם־הָפֵר יָפֵר אֹתָם אַחֲרֵי שָׁמְעוֹ וְנָשָׂא אֶת־עֲוֺנָהּ׃
אֵלֶּה הַחֻקִּים אֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה בֵּין אִישׁ לְאִשְׁתּוֹ בֵּין־אָב לְבִתּוֹ בִּנְעֻרֶיהָ בֵּית אָבִיהָ׃

Chapter 31

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
נְקֹם נִקְמַת בְּנֵי יִשְׂרָאֵל מֵאֵת הַמִּדְיָנִים אַחַר תֵּאָסֵף אֶל־עַמֶּיךָ׃
וַיְדַבֵּר מֹשֶׁה אֶל־הָעָם לֵאמֹר הֵחָלְצוּ מֵאִתְּכֶם אֲנָשִׁים לַצָּבָא וְיִהְיוּ עַל־מִדְיָן לָתֵת נִקְמַת־יְהוָה בְּמִדְיָן׃
אֶלֶף לַמַּטֶּה אֶלֶף לַמַּטֶּה לְכֹל מַטּוֹת יִשְׂרָאֵל תִּשְׁלְחוּ לַצָּבָא׃
וַיִּמָּסְרוּ מֵאַלְפֵי יִשְׂרָאֵל אֶלֶף לַמַּטֶּה שְׁנֵים־עָשָׂר אֶלֶף חֲלוּצֵי צָבָא׃
וַיִּשְׁלַח אֹתָם מֹשֶׁה אֶלֶף לַמַּטֶּה לַצָּבָא אֹתָם וְאֶת־פִּינְחָס בֶּן־אֶלְעָזָר הַכֹּהֵן לַצָּבָא וּכְלֵי הַקֹּדֶשׁ וַחֲצֹצְרוֹת הַתְּרוּעָה בְּיָדוֹ׃
וַיִּצְבְּאוּ עַל־מִדְיָן כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה וַיַּהַרְגוּ כָּל־זָכָר׃
וְאֶת־מַלְכֵי מִדְיָן הָרְגוּ עַל־חַלְלֵיהֶם אֶת־אֱוִי וְאֶת־רֶקֶם וְאֶת־צוּר וְאֶת־חוּר וְאֶת־רֶבַע חֲמֵשֶׁת מַלְכֵי מִדְיָן וְאֵת בִּלְעָם בֶּן־בְּעוֹר הָרְגוּ בֶּחָרֶב׃
וַיִּשְׁבּוּ בְנֵי־יִשְׂרָאֵל אֶת־נְשֵׁי מִדְיָן וְאֶת־טַפָּם וְאֵת כָּל־בְּהֶמְתָּם וְאֶת־כָּל־מִקְנֵהֶם וְאֶת־כָּל־חֵילָם בָּזָזוּ׃
וְאֵת כָּל־עָרֵיהֶם בְּמוֹשְׁבֹתָם וְאֵת כָּל־טִירֹתָם שָׂרְפוּ בָּאֵשׁ׃
וַיִּקְחוּ אֶת־כָּל־הַשָּׁלָל וְאֵת כָּל־הַמַּלְקוֹחַ בָּאָדָם וּבַבְּהֵמָה׃
וַיָּבִאוּ אֶל־מֹשֶׁה וְאֶל־אֶלְעָזָר הַכֹּהֵן וְאֶל־עֲדַת בְּנֵי־יִשְׂרָאֵל אֶת־הַשְּׁבִי וְאֶת־הַמַּלְקוֹחַ וְאֶת־הַשָּׁלָל אֶל־הַמַּחֲנֶה אֶל־עַרְבֹת מוֹאָב אֲשֶׁר עַל־יַרְדֵּן יְרֵחוֹ׃
וַיֵּצְאוּ מֹשֶׁה וְאֶלְעָזָר הַכֹּהֵן וְכָל־נְשִׂיאֵי הָעֵדָה לִקְרָאתָם אֶל־מִחוּץ לַמַּחֲנֶה׃
וַיִּקְצֹף מֹשֶׁה עַל פְּקוּדֵי הֶחָיִל שָׂרֵי הָאֲלָפִים וְשָׂרֵי הַמֵּאוֹת הַבָּאִים מִצְּבָא הַמִּלְחָמָה׃
וַיֹּאמֶר אֲלֵיהֶם מֹשֶׁה הַחִיִּיתֶם כָּל־נְקֵבָה׃
הֵן הֵנָּה הָיוּ לִבְנֵי יִשְׂרָאֵל בִּדְבַר בִּלְעָם לִמְסָר־מַעַל בַּיהוָה עַל־דְּבַר־פְּעוֹר וַתְּהִי הַמַּגֵּפָה בַּעֲדַת יְהוָה׃
וְעַתָּה הִרְגוּ כָל־זָכָר בַּטָּף וְכָל־אִשָּׁה יֹדַעַת אִישׁ לְמִשְׁכַּב זָכָר הֲרֹגוּ׃
וְכֹל הַטַּף בַּנָּשִׁים אֲשֶׁר לֹא־יָדְעוּ מִשְׁכַּב זָכָר הַחֲיוּ לָכֶם׃
וְאַתֶּם חֲנוּ מִחוּץ לַמַּחֲנֶה שִׁבְעַת יָמִים כֹּל הֹרֵג נֶפֶשׁ וְכֹל נֹגֵעַ בֶּחָלָל תִּתְחַטְּאוּ בַּיּוֹם הַשְּׁלִישִׁי וּבַיּוֹם הַשְּׁבִיעִי אַתֶּם וּשְׁבִיכֶם׃
וְכָל־בֶּגֶד וְכָל־כְּלִי־עוֹר וְכָל־מַעֲשֵׂה עִזִּים וְכָל־כְּלִי־עֵץ תִּתְחַטָּאוּ׃
וַיֹּאמֶר אֶלְעָזָר הַכֹּהֵן אֶל־אַנְשֵׁי הַצָּבָא הַבָּאִים לַמִּלְחָמָה זֹאת חֻקַּת הַתּוֹרָה אֲשֶׁר־צִוָּה יְהוָה אֶת־מֹשֶׁה׃
אַךְ אֶת־הַזָּהָב וְאֶת־הַכָּסֶף אֶת־הַנְּחֹשֶׁת אֶת־הַבַּרְזֶל אֶת־הַבְּדִיל וְאֶת־הָעֹפָרֶת׃
כָּל־דָּבָר אֲשֶׁר־יָבֹא בָאֵשׁ תַּעֲבִירוּ בָאֵשׁ וְטָהֵר אַךְ בְּמֵי נִדָּה יִתְחַטָּא וְכֹל אֲשֶׁר לֹא־יָבֹא בָּאֵשׁ תַּעֲבִירוּ בַמָּיִם׃
וְכִבַּסְתֶּם בִּגְדֵיכֶם בַּיּוֹם הַשְּׁבִיעִי וּטְהַרְתֶּם וְאַחַר תָּבֹאוּ אֶל־הַמַּחֲנֶה׃
וַיֹּאמֶר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
שָׂא אֵת רֹאשׁ מַלְקוֹחַ הַשְּׁבִי בָּאָדָם וּבַבְּהֵמָה אַתָּה וְאֶלְעָזָר הַכֹּהֵן וְרָאשֵׁי אֲבוֹת הָעֵדָה׃
וְחָצִיתָ אֶת־הַמַּלְקוֹחַ בֵּין תֹּפְשֵׂי הַמִּלְחָמָה הַיֹּצְאִים לַצָּבָא וּבֵין כָּל־הָעֵדָה׃
וַהֲרֵמֹתָ מֶכֶס לַיהוָה מֵאֵת אַנְשֵׁי הַמִּלְחָמָה הַיֹּצְאִים לַצָּבָא אֶחָד נֶפֶשׁ מֵחֲמֵשׁ הַמֵּאוֹת מִן־הָאָדָם וּמִן־הַבָּקָר וּמִן־הַחֲמֹרִים וּמִן־הַצֹּאן׃
מִמַּחֲצִיתָם תִּקָּחוּ וְנָתַתָּה לְאֶלְעָזָר הַכֹּהֵן תְּרוּמַת יְהוָה׃
וּמִמַּחֲצִת בְּנֵי־יִשְׂרָאֵל תִּקַּח אֶחָד אָחֻז מִן־הַחֲמִשִּׁים מִן־הָאָדָם מִן־הַבָּקָר מִן־הַחֲמֹרִים וּמִן־הַצֹּאן מִכָּל־הַבְּהֵמָה וְנָתַתָּה אֹתָם לַלְוִיִּם שֹׁמְרֵי מִשְׁמֶרֶת מִשְׁכַּן יְהוָה׃
וַיַּעַשׂ מֹשֶׁה וְאֶלְעָזָר הַכֹּהֵן כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיְהִי הַמַּלְקוֹחַ יֶתֶר הַבָּז אֲשֶׁר בָּזְזוּ עַם הַצָּבָא צֹאן שֵׁשׁ־מֵאוֹת אֶלֶף וְשִׁבְעִים אֶלֶף וַחֲמֵשֶׁת־אֲלָפִים׃
וּבָקָר שְׁנַיִם וְשִׁבְעִים אָלֶף׃
וַחֲמֹרִים אֶחָד וְשִׁשִּׁים אָלֶף׃
וְנֶפֶשׁ אָדָם מִן־הַנָּשִׁים אֲשֶׁר לֹא־יָדְעוּ מִשְׁכַּב זָכָר כָּל־נֶפֶשׁ שְׁנַיִם וּשְׁלֹשִׁים אָלֶף׃
וַתְּהִי הַמֶּחֱצָה חֵלֶק הַיֹּצְאִים בַּצָּבָא מִסְפַּר הַצֹּאן שְׁלֹשׁ־מֵאוֹת אֶלֶף וּשְׁלֹשִׁים אֶלֶף וְשִׁבְעַת אֲלָפִים וַחֲמֵשׁ מֵאוֹת׃
וַיְהִי הַמֶּכֶס לַיהוָה מִן־הַצֹּאן שֵׁשׁ מֵאוֹת חָמֵשׁ וְשִׁבְעִים׃
וְהַבָּקָר שִׁשָּׁה וּשְׁלֹשִׁים אָלֶף וּמִכְסָם לַיהוָה שְׁנַיִם וְשִׁבְעִים׃
וַחֲמֹרִים שְׁלֹשִׁים אֶלֶף וַחֲמֵשׁ מֵאוֹת וּמִכְסָם לַיהוָה אֶחָד וְשִׁשִּׁים׃
וְנֶפֶשׁ אָדָם שִׁשָּׁה עָשָׂר אָלֶף וּמִכְסָם לַיהוָה שְׁנַיִם וּשְׁלֹשִׁים נָפֶשׁ׃
וַיִּתֵּן מֹשֶׁה אֶת־מֶכֶס תְּרוּמַת יְהוָה לְאֶלְעָזָר הַכֹּהֵן כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וּמִמַּחֲצִית בְּנֵי יִשְׂרָאֵל אֲשֶׁר חָצָה מֹשֶׁה מִן־הָאֲנָשִׁים הַצֹּבְאִים׃
וַתְּהִי מֶחֱצַת הָעֵדָה מִן־הַצֹּאן שְׁלֹשׁ־מֵאוֹת אֶלֶף וּשְׁלֹשִׁים אֶלֶף שִׁבְעַת אֲלָפִים וַחֲמֵשׁ מֵאוֹת׃
וּבָקָר שִׁשָּׁה וּשְׁלֹשִׁים אָלֶף׃
וַחֲמֹרִים שְׁלֹשִׁים אֶלֶף וַחֲמֵשׁ מֵאוֹת׃
וְנֶפֶשׁ אָדָם שִׁשָּׁה עָשָׂר אָלֶף׃
וַיִּקַּח מֹשֶׁה מִמַּחֲצִת בְּנֵי־יִשְׂרָאֵל אֶת־הָאָחֻז אֶחָד מִן־הַחֲמִשִּׁים מִן־הָאָדָם וּמִן־הַבְּהֵמָה וַיִּתֵּן אֹתָם לַלְוִיִּם שֹׁמְרֵי מִשְׁמֶרֶת מִשְׁכַּן יְהוָה כַּאֲשֶׁר צִוָּה יְהוָה אֶת־מֹשֶׁה׃
וַיִּקְרְבוּ אֶל־מֹשֶׁה הַפְּקֻדִים אֲשֶׁר לְאַלְפֵי הַצָּבָא שָׂרֵי הָאֲלָפִים וְשָׂרֵי הַמֵּאוֹת׃
וַיֹּאמְרוּ אֶל־מֹשֶׁה עֲבָדֶיךָ נָשְׂאוּ אֶת־רֹאשׁ אַנְשֵׁי הַמִּלְחָמָה אֲשֶׁר בְּיָדֵנוּ וְלֹא־נִפְקַד מִמֶּנּוּ אִישׁ׃
וַנַּקְרֵב אֶת־קָרְבַּן יְהוָה אִישׁ אֲשֶׁר מָצָא כְלִי־זָהָב אֶצְעָדָה וְצָמִיד טַבַּעַת עָגִיל וְכוּמָז לְכַפֵּר עַל־נַפְשֹׁתֵינוּ לִפְנֵי יְהוָה׃
וַיִּקַּח מֹשֶׁה וְאֶלְעָזָר הַכֹּהֵן אֶת־הַזָּהָב מֵאִתָּם כֹּל כְּלִי מַעֲשֶׂה׃
וַיְהִי כָּל־זְהַב הַתְּרוּמָה אֲשֶׁר הֵרִימוּ לַיהוָה שִׁשָּׁה עָשָׂר אֶלֶף שְׁבַע־מֵאוֹת וַחֲמִשִּׁים שָׁקֶל מֵאֵת שָׂרֵי הָאֲלָפִים וּמֵאֵת שָׂרֵי הַמֵּאוֹת׃
אַנְשֵׁי הַצָּבָא בָּזְזוּ אִישׁ לוֹ׃
וַיִּקַּח מֹשֶׁה וְאֶלְעָזָר הַכֹּהֵן אֶת־הַזָּהָב מֵאֵת שָׂרֵי הָאֲלָפִים וְהַמֵּאוֹת וַיָּבִאוּ אֹתוֹ אֶל־אֹהֶל מוֹעֵד זִכָּרוֹן לִבְנֵי־יִשְׂרָאֵל לִפְנֵי יְהוָה׃

Chapter 32

וּמִקְנֶה רַב הָיָה לִבְנֵי רְאוּבֵן וְלִבְנֵי־גָד עָצוּם מְאֹד וַיִּרְאוּ אֶת־אֶרֶץ יַעְזֵר וְאֶת־אֶרֶץ גִּלְעָד וְהִנֵּה הַמָּקוֹם מְקוֹם מִקְנֶה׃
וַיָּבֹאוּ בְנֵי־גָד וּבְנֵי רְאוּבֵן וַיֹּאמְרוּ אֶל־מֹשֶׁה וְאֶל־אֶלְעָזָר הַכֹּהֵן וְאֶל־נְשִׂיאֵי הָעֵדָה לֵאמֹר׃
עֲטָרוֹת וְדִיבֹן וְיַעְזֵר וְנִמְרָה וְחֶשְׁבּוֹן וְאֶלְעָלֵה וּשְׂבָם וּנְבוֹ וּבְעֹן׃
הָאָרֶץ אֲשֶׁר הִכָּה יְהוָה לִפְנֵי עֲדַת יִשְׂרָאֵל אֶרֶץ מִקְנֶה הִוא וְלַעֲבָדֶיךָ מִקְנֶה׃
וַיֹּאמְרוּ אִם־מָצָאנוּ חֵן בְּעֵינֶיךָ יֻתַּן אֶת־הָאָרֶץ הַזֹּאת לַעֲבָדֶיךָ לַאֲחֻזָּה אַל־תַּעֲבִרֵנוּ אֶת־הַיַּרְדֵּן׃
וַיֹּאמֶר מֹשֶׁה לִבְנֵי־גָד וְלִבְנֵי רְאוּבֵן הַאַחֵיכֶם יָבֹאוּ לַמִּלְחָמָה וְאַתֶּם תֵּשְׁבוּ פֹה׃
וְלָמָּה תנואון [תְנִיאוּן] אֶת־לֵב בְּנֵי יִשְׂרָאֵל מֵעֲבֹר אֶל־הָאָרֶץ אֲשֶׁר־נָתַן לָהֶם יְהוָה׃
כֹּה עָשׂוּ אֲבֹתֵיכֶם בְּשָׁלְחִי אֹתָם מִקָּדֵשׁ בַּרְנֵעַ לִרְאוֹת אֶת־הָאָרֶץ׃
וַיַּעֲלוּ עַד־נַחַל אֶשְׁכּוֹל וַיִּרְאוּ אֶת־הָאָרֶץ וַיָּנִיאוּ אֶת־לֵב בְּנֵי יִשְׂרָאֵל לְבִלְתִּי־בֹא אֶל־הָאָרֶץ אֲשֶׁר־נָתַן לָהֶם יְהוָה׃
וַיִּחַר־אַף יְהוָה בַּיּוֹם הַהוּא וַיִּשָּׁבַע לֵאמֹר׃
אִם־יִרְאוּ הָאֲנָשִׁים הָעֹלִים מִמִּצְרַיִם מִבֶּן עֶשְׂרִים שָׁנָה וָמַעְלָה אֵת הָאֲדָמָה אֲשֶׁר נִשְׁבַּעְתִּי לְאַבְרָהָם לְיִצְחָק וּלְיַעֲקֹב כִּי לֹא־מִלְאוּ אַחֲרָי׃
בִּלְתִּי כָּלֵב בֶּן־יְפֻנֶּה הַקְּנִזִּי וִיהוֹשֻׁעַ בִּן־נוּן כִּי מִלְאוּ אַחֲרֵי יְהוָה׃
וַיִּחַר־אַף יְהוָה בְּיִשְׂרָאֵל וַיְנִעֵם בַּמִּדְבָּר אַרְבָּעִים שָׁנָה עַד־תֹּם כָּל־הַדּוֹר הָעֹשֶׂה הָרַע בְּעֵינֵי יְהוָה׃
וְהִנֵּה קַמְתֶּם תַּחַת אֲבֹתֵיכֶם תַּרְבּוּת אֲנָשִׁים חַטָּאִים לִסְפּוֹת עוֹד עַל חֲרוֹן אַף־יְהוָה אֶל־יִשְׂרָאֵל׃
כִּי תְשׁוּבֻן מֵאַחֲרָיו וְיָסַף עוֹד לְהַנִּיחוֹ בַּמִּדְבָּר וְשִׁחַתֶּם לְכָל־הָעָם הַזֶּה׃
וַיִּגְּשׁוּ אֵלָיו וַיֹּאמְרוּ גִּדְרֹת צֹאן נִבְנֶה לְמִקְנֵנוּ פֹּה וְעָרִים לְטַפֵּנוּ׃
וַאֲנַחְנוּ נֵחָלֵץ חֻשִׁים לִפְנֵי בְּנֵי יִשְׂרָאֵל עַד אֲשֶׁר אִם־הֲבִיאֹנֻם אֶל־מְקוֹמָם וְיָשַׁב טַפֵּנוּ בְּעָרֵי הַמִּבְצָר מִפְּנֵי יֹשְׁבֵי הָאָרֶץ׃
לֹא נָשׁוּב אֶל־בָּתֵּינוּ עַד הִתְנַחֵל בְּנֵי יִשְׂרָאֵל אִישׁ נַחֲלָתוֹ׃
כִּי לֹא נִנְחַל אִתָּם מֵעֵבֶר לַיַּרְדֵּן וָהָלְאָה כִּי בָאָה נַחֲלָתֵנוּ אֵלֵינוּ מֵעֵבֶר הַיַּרְדֵּן מִזְרָחָה׃
וַיֹּאמֶר אֲלֵיהֶם מֹשֶׁה אִם־תַּעֲשׂוּן אֶת־הַדָּבָר הַזֶּה אִם־תֵּחָלְצוּ לִפְנֵי יְהוָה לַמִּלְחָמָה׃
וְעָבַר לָכֶם כָּל־חָלוּץ אֶת־הַיַּרְדֵּן לִפְנֵי יְהוָה עַד הוֹרִישׁוֹ אֶת־אֹיְבָיו מִפָּנָיו׃
וְנִכְבְּשָׁה הָאָרֶץ לִפְנֵי יְהוָה וְאַחַר תָּשֻׁבוּ וִהְיִיתֶם נְקִיִּים מֵיְהוָה וּמִיִּשְׂרָאֵל וְהָיְתָה הָאָרֶץ הַזֹּאת לָכֶם לַאֲחֻזָּה לִפְנֵי יְהוָה׃
וְאִם־לֹא תַעֲשׂוּן כֵּן הִנֵּה חֲטָאתֶם לַיהוָה וּדְעוּ חַטַּאתְכֶם אֲשֶׁר תִּמְצָא אֶתְכֶם׃
בְּנוּ־לָכֶם עָרִים לְטַפְּכֶם וּגְדֵרֹת לְצֹנַאֲכֶם וְהַיֹּצֵא מִפִּיכֶם תַּעֲשׂוּ׃
וַיֹּאמֶר בְּנֵי־גָד וּבְנֵי רְאוּבֵן אֶל־מֹשֶׁה לֵאמֹר עֲבָדֶיךָ יַעֲשׂוּ כַּאֲשֶׁר אֲדֹנִי מְצַוֶּה׃
טַפֵּנוּ נָשֵׁינוּ מִקְנֵנוּ וְכָל־בְּהֶמְתֵּנוּ יִהְיוּ־שָׁם בְּעָרֵי הַגִּלְעָד׃
וַעֲבָדֶיךָ יַעַבְרוּ כָּל־חֲלוּץ צָבָא לִפְנֵי יְהוָה לַמִּלְחָמָה כַּאֲשֶׁר אֲדֹנִי דֹּבֵר׃
וַיְצַו לָהֶם מֹשֶׁה אֵת אֶלְעָזָר הַכֹּהֵן וְאֵת יְהוֹשֻׁעַ בִּן־נוּן וְאֶת־רָאשֵׁי אֲבוֹת הַמַּטּוֹת לִבְנֵי יִשְׂרָאֵל׃
וַיֹּאמֶר מֹשֶׁה אֲלֵהֶם אִם־יַעַבְרוּ בְנֵי־גָד וּבְנֵי־רְאוּבֵן אִתְּכֶם אֶת־הַיַּרְדֵּן כָּל־חָלוּץ לַמִּלְחָמָה לִפְנֵי יְהוָה וְנִכְבְּשָׁה הָאָרֶץ לִפְנֵיכֶם וּנְתַתֶּם לָהֶם אֶת־אֶרֶץ הַגִּלְעָד לַאֲחֻזָּה׃
וְאִם־לֹא יַעַבְרוּ חֲלוּצִים אִתְּכֶם וְנֹאחֲזוּ בְתֹכְכֶם בְּאֶרֶץ כְּנָעַן׃
וַיַּעֲנוּ בְנֵי־גָד וּבְנֵי רְאוּבֵן לֵאמֹר אֵת אֲשֶׁר דִּבֶּר יְהוָה אֶל־עֲבָדֶיךָ כֵּן נַעֲשֶׂה׃
נַחְנוּ נַעֲבֹר חֲלוּצִים לִפְנֵי יְהוָה אֶרֶץ כְּנָעַן וְאִתָּנוּ אֲחֻזַּת נַחֲלָתֵנוּ מֵעֵבֶר לַיַּרְדֵּן׃
וַיִּתֵּן לָהֶם מֹשֶׁה לִבְנֵי־גָד וְלִבְנֵי רְאוּבֵן וְלַחֲצִי שֵׁבֶט מְנַשֶּׁה בֶן־יוֹסֵף אֶת־מַמְלֶכֶת סִיחֹן מֶלֶךְ הָאֱמֹרִי וְאֶת־מַמְלֶכֶת עוֹג מֶלֶךְ הַבָּשָׁן הָאָרֶץ לְעָרֶיהָ בִּגְבֻלֹת עָרֵי הָאָרֶץ סָבִיב׃
וַיִּבְנוּ בְנֵי־גָד אֶת־דִּיבֹן וְאֶת־עֲטָרֹת וְאֵת עֲרֹעֵר׃
וְאֶת־עַטְרֹת שׁוֹפָן וְאֶת־יַעְזֵר וְיָגְבֳּהָה׃
וְאֶת־בֵּית נִמְרָה וְאֶת־בֵּית הָרָן עָרֵי מִבְצָר וְגִדְרֹת צֹאן׃
וּבְנֵי רְאוּבֵן בָּנוּ אֶת־חֶשְׁבּוֹן וְאֶת־אֶלְעָלֵא וְאֵת קִרְיָתָיִם׃
וְאֶת־נְבוֹ וְאֶת־בַּעַל מְעוֹן מוּסַבֹּת שֵׁם וְאֶת־שִׂבְמָה וַיִּקְרְאוּ בְשֵׁמֹת אֶת־שְׁמוֹת הֶעָרִים אֲשֶׁר בָּנוּ׃
וַיֵּלְכוּ בְּנֵי מָכִיר בֶּן־מְנַשֶּׁה גִּלְעָדָה וַיִּלְכְּדֻהָ וַיּוֹרֶשׁ אֶת־הָאֱמֹרִי אֲשֶׁר־בָּהּ׃
וַיִּתֵּן מֹשֶׁה אֶת־הַגִּלְעָד לְמָכִיר בֶּן־מְנַשֶּׁה וַיֵּשֶׁב בָּהּ׃
וְיָאִיר בֶּן־מְנַשֶּׁה הָלַךְ וַיִּלְכֹּד אֶת־חַוֺּתֵיהֶם וַיִּקְרָא אֶתְהֶן חַוֺּת יָאִיר׃
וְנֹבַח הָלַךְ וַיִּלְכֹּד אֶת־קְנָת וְאֶת־בְּנֹתֶיהָ וַיִּקְרָא לָה נֹבַח בִּשְׁמוֹ׃

Chapter 33

אֵלֶּה מַסְעֵי בְנֵי־יִשְׂרָאֵל אֲשֶׁר יָצְאוּ מֵאֶרֶץ מִצְרַיִם לְצִבְאֹתָם בְּיַד־מֹשֶׁה וְאַהֲרֹן׃
וַיִּכְתֹּב מֹשֶׁה אֶת־מוֹצָאֵיהֶם לְמַסְעֵיהֶם עַל־פִּי יְהוָה וְאֵלֶּה מַסְעֵיהֶם לְמוֹצָאֵיהֶם׃
וַיִּסְעוּ מֵרַעְמְסֵס בַּחֹדֶשׁ הָרִאשׁוֹן בַּחֲמִשָּׁה עָשָׂר יוֹם לַחֹדֶשׁ הָרִאשׁוֹן מִמָּחֳרַת הַפֶּסַח יָצְאוּ בְנֵי־יִשְׂרָאֵל בְּיָד רָמָה לְעֵינֵי כָּל־מִצְרָיִם׃
וּמִצְרַיִם מְקַבְּרִים אֵת אֲשֶׁר הִכָּה יְהוָה בָּהֶם כָּל־בְּכוֹר וּבֵאלֹהֵיהֶם עָשָׂה יְהוָה שְׁפָטִים׃
וַיִּסְעוּ בְנֵי־יִשְׂרָאֵל מֵרַעְמְסֵס וַיַּחֲנוּ בְּסֻכֹּת׃
וַיִּסְעוּ מִסֻּכֹּת וַיַּחֲנוּ בְאֵתָם אֲשֶׁר בִּקְצֵה הַמִּדְבָּר׃
וַיִּסְעוּ מֵאֵתָם וַיָּשָׁב עַל־פִּי הַחִירֹת אֲשֶׁר עַל־פְּנֵי בַּעַל צְפוֹן וַיַּחֲנוּ לִפְנֵי מִגְדֹּל׃
וַיִּסְעוּ מִפְּנֵי הַחִירֹת וַיַּעַבְרוּ בְתוֹךְ־הַיָּם הַמִּדְבָּרָה וַיֵּלְכוּ דֶּרֶךְ שְׁלֹשֶׁת יָמִים בְּמִדְבַּר אֵתָם וַיַּחֲנוּ בְּמָרָה׃
וַיִּסְעוּ מִמָּרָה וַיָּבֹאוּ אֵילִמָה וּבְאֵילִם שְׁתֵּים עֶשְׂרֵה עֵינֹת מַיִם וְשִׁבְעִים תְּמָרִים וַיַּחֲנוּ־שָׁם׃
וַיִּסְעוּ מֵאֵילִם וַיַּחֲנוּ עַל־יַם־סוּף׃
וַיִּסְעוּ מִיַּם־סוּף וַיַּחֲנוּ בְּמִדְבַּר־סִין׃
וַיִּסְעוּ מִמִּדְבַּר־סִין וַיַּחֲנוּ בְּדָפְקָה׃
וַיִּסְעוּ מִדָּפְקָה וַיַּחֲנוּ בְּאָלוּשׁ׃
וַיִּסְעוּ מֵאָלוּשׁ וַיַּחֲנוּ בִּרְפִידִם וְלֹא־הָיָה שָׁם מַיִם לָעָם לִשְׁתּוֹת׃
וַיִּסְעוּ מֵרְפִידִם וַיַּחֲנוּ בְּמִדְבַּר סִינָי׃
וַיִּסְעוּ מִמִּדְבַּר סִינָי וַיַּחֲנוּ בְּקִבְרֹת הַתַּאֲוָה׃
וַיִּסְעוּ מִקִּבְרֹת הַתַּאֲוָה וַיַּחֲנוּ בַּחֲצֵרֹת׃
וַיִּסְעוּ מֵחֲצֵרֹת וַיַּחֲנוּ בְּרִתְמָה׃
וַיִּסְעוּ מֵרִתְמָה וַיַּחֲנוּ בְּרִמֹּן פָּרֶץ׃
וַיִּסְעוּ מֵרִמֹּן פָּרֶץ וַיַּחֲנוּ בְּלִבְנָה׃
וַיִּסְעוּ מִלִּבְנָה וַיַּחֲנוּ בְּרִסָּה׃
וַיִּסְעוּ מֵרִסָּה וַיַּחֲנוּ בִּקְהֵלָתָה׃
וַיִּסְעוּ מִקְּהֵלָתָה וַיַּחֲנוּ בְּהַר־שָׁפֶר׃
וַיִּסְעוּ מֵהַר־שָׁפֶר וַיַּחֲנוּ בַּחֲרָדָה׃
וַיִּסְעוּ מֵחֲרָדָה וַיַּחֲנוּ בְּמַקְהֵלֹת׃
וַיִּסְעוּ מִמַּקְהֵלֹת וַיַּחֲנוּ בְּתָחַת׃
וַיִּסְעוּ מִתָּחַת וַיַּחֲנוּ בְּתָרַח׃
וַיִּסְעוּ מִתָּרַח וַיַּחֲנוּ בְּמִתְקָה׃
וַיִּסְעוּ מִמִּתְקָה וַיַּחֲנוּ בְּחַשְׁמֹנָה׃
וַיִּסְעוּ מֵחַשְׁמֹנָה וַיַּחֲנוּ בְּמֹסֵרוֹת׃
וַיִּסְעוּ מִמֹּסֵרוֹת וַיַּחֲנוּ בִּבְנֵי יַעֲקָן׃
וַיִּסְעוּ מִבְּנֵי יַעֲקָן וַיַּחֲנוּ בְּחֹר הַגִּדְגָּד׃
וַיִּסְעוּ מֵחֹר הַגִּדְגָּד וַיַּחֲנוּ בְּיָטְבָתָה׃
וַיִּסְעוּ מִיָּטְבָתָה וַיַּחֲנוּ בְּעַבְרֹנָה׃
וַיִּסְעוּ מֵעַבְרֹנָה וַיַּחֲנוּ בְּעֶצְיוֹן גָּבֶר׃
וַיִּסְעוּ מֵעֶצְיוֹן גָּבֶר וַיַּחֲנוּ בְמִדְבַּר־צִן הִוא קָדֵשׁ׃
וַיִּסְעוּ מִקָּדֵשׁ וַיַּחֲנוּ בְּהֹר הָהָר בִּקְצֵה אֶרֶץ אֱדוֹם׃
וַיַּעַל אַהֲרֹן הַכֹּהֵן אֶל־הֹר הָהָר עַל־פִּי יְהוָה וַיָּמָת שָׁם בִּשְׁנַת הָאַרְבָּעִים לְצֵאת בְּנֵי־יִשְׂרָאֵל מֵאֶרֶץ מִצְרַיִם בַּחֹדֶשׁ הַחֲמִישִׁי בְּאֶחָד לַחֹדֶשׁ׃
וְאַהֲרֹן בֶּן־שָׁלֹשׁ וְעֶשְׂרִים וּמְאַת שָׁנָה בְּמֹתוֹ בְּהֹר הָהָר׃
וַיִּשְׁמַע הַכְּנַעֲנִי מֶלֶךְ עֲרָד וְהוּא־יֹשֵׁב בַּנֶּגֶב בְּאֶרֶץ כְּנָעַן בְּבֹא בְּנֵי יִשְׂרָאֵל׃
וַיִּסְעוּ מֵהֹר הָהָר וַיַּחֲנוּ בְּצַלְמֹנָה׃
וַיִּסְעוּ מִצַּלְמֹנָה וַיַּחֲנוּ בְּפוּנֹן׃
וַיִּסְעוּ מִפּוּנֹן וַיַּחֲנוּ בְּאֹבֹת׃
וַיִּסְעוּ מֵאֹבֹת וַיַּחֲנוּ בְּעִיֵּי הָעֲבָרִים בִּגְבוּל מוֹאָב׃
וַיִּסְעוּ מֵעִיִּים וַיַּחֲנוּ בְּדִיבֹן גָּד׃
וַיִּסְעוּ מִדִּיבֹן גָּד וַיַּחֲנוּ בְּעַלְמֹן דִּבְלָתָיְמָה׃
וַיִּסְעוּ מֵעַלְמֹן דִּבְלָתָיְמָה וַיַּחֲנוּ בְּהָרֵי הָעֲבָרִים לִפְנֵי נְבוֹ׃
וַיִּסְעוּ מֵהָרֵי הָעֲבָרִים וַיַּחֲנוּ בְּעַרְבֹת מוֹאָב עַל יַרְדֵּן יְרֵחוֹ׃
וַיַּחֲנוּ עַל־הַיַּרְדֵּן מִבֵּית הַיְשִׁמֹת עַד אָבֵל הַשִּׁטִּים בְּעַרְבֹת מוֹאָב׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה בְּעַרְבֹת מוֹאָב עַל־יַרְדֵּן יְרֵחוֹ לֵאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם כִּי אַתֶּם עֹבְרִים אֶת־הַיַּרְדֵּן אֶל־אֶרֶץ כְּנָעַן׃
וְהוֹרַשְׁתֶּם אֶת־כָּל־יֹשְׁבֵי הָאָרֶץ מִפְּנֵיכֶם וְאִבַּדְתֶּם אֵת כָּל־מַשְׂכִּיֹּתָם וְאֵת כָּל־צַלְמֵי מַסֵּכֹתָם תְּאַבֵּדוּ וְאֵת כָּל־בָּמֹתָם תַּשְׁמִידוּ׃
וְהוֹרַשְׁתֶּם אֶת־הָאָרֶץ וִישַׁבְתֶּם־בָּהּ כִּי לָכֶם נָתַתִּי אֶת־הָאָרֶץ לָרֶשֶׁת אֹתָהּ׃
וְהִתְנַחַלְתֶּם אֶת־הָאָרֶץ בְּגוֹרָל לְמִשְׁפְּחֹתֵיכֶם לָרַב תַּרְבּוּ אֶת־נַחֲלָתוֹ וְלַמְעַט תַּמְעִיט אֶת־נַחֲלָתוֹ אֶל אֲשֶׁר־יֵצֵא לוֹ שָׁמָּה הַגּוֹרָל לוֹ יִהְיֶה לְמַטּוֹת אֲבֹתֵיכֶם תִּתְנֶחָלוּ׃
וְאִם־לֹא תוֹרִישׁוּ אֶת־יֹשְׁבֵי הָאָרֶץ מִפְּנֵיכֶם וְהָיָה אֲשֶׁר תּוֹתִירוּ מֵהֶם לְשִׂכִּים בְּעֵינֵיכֶם וְלִצְנִינִם בְּצִדֵּיכֶם וְצָרֲרוּ אֶתְכֶם עַל־הָאָרֶץ אֲשֶׁר אַתֶּם יֹשְׁבִים בָּהּ׃
וְהָיָה כַּאֲשֶׁר דִּמִּיתִי לַעֲשׂוֹת לָהֶם אֶעֱשֶׂה לָכֶם׃

Chapter 34

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
צַו אֶת־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם כִּי־אַתֶּם בָּאִים אֶל־הָאָרֶץ כְּנָעַן זֹאת הָאָרֶץ אֲשֶׁר תִּפֹּל לָכֶם בְּנַחֲלָה אֶרֶץ כְּנַעַן לִגְבֻלֹתֶיהָ׃
וְהָיָה לָכֶם פְּאַת־נֶגֶב מִמִּדְבַּר־צִן עַל־יְדֵי אֱדוֹם וְהָיָה לָכֶם גְּבוּל נֶגֶב מִקְצֵה יָם־הַמֶּלַח קֵדְמָה׃
וְנָסַב לָכֶם הַגְּבוּל מִנֶּגֶב לְמַעֲלֵה עַקְרַבִּים וְעָבַר צִנָה והיה [וְהָיוּ] תּוֹצְאֹתָיו מִנֶּגֶב לְקָדֵשׁ בַּרְנֵעַ וְיָצָא חֲצַר־אַדָּר וְעָבַר עַצְמֹנָה׃
וְנָסַב הַגְּבוּל מֵעַצְמוֹן נַחְלָה מִצְרָיִם וְהָיוּ תוֹצְאֹתָיו הַיָּמָּה׃
וּגְבוּל יָם וְהָיָה לָכֶם הַיָּם הַגָּדוֹל וּגְבוּל זֶה־יִהְיֶה לָכֶם גְּבוּל יָם׃
וְזֶה־יִהְיֶה לָכֶם גְּבוּל צָפוֹן מִן־הַיָּם הַגָּדֹל תְּתָאוּ לָכֶם הֹר הָהָר׃
מֵהֹר הָהָר תְּתָאוּ לְבֹא חֲמָת וְהָיוּ תּוֹצְאֹת הַגְּבֻל צְדָדָה׃
וְיָצָא הַגְּבֻל זִפְרֹנָה וְהָיוּ תוֹצְאֹתָיו חֲצַר עֵינָן זֶה־יִהְיֶה לָכֶם גְּבוּל צָפוֹן׃
וְהִתְאַוִּיתֶם לָכֶם לִגְבוּל קֵדְמָה מֵחֲצַר עֵינָן שְׁפָמָה׃
וְיָרַד הַגְּבֻל מִשְּׁפָם הָרִבְלָה מִקֶּדֶם לָעָיִן וְיָרַד הַגְּבוּל וּמָחָה עַל־כֶּתֶף יָם־כִּנֶּרֶת קֵדְמָה׃
וְיָרַד הַגְּבוּל הַיַּרְדֵּנָה וְהָיוּ תוֹצְאֹתָיו יָם הַמֶּלַח זֹאת תִּהְיֶה לָכֶם הָאָרֶץ לִגְבֻלֹתֶיהָ סָבִיב׃
וַיְצַו מֹשֶׁה אֶת־בְּנֵי יִשְׂרָאֵל לֵאמֹר זֹאת הָאָרֶץ אֲשֶׁר תִּתְנַחֲלוּ אֹתָהּ בְּגוֹרָל אֲשֶׁר צִוָּה יְהוָה לָתֵת לְתִשְׁעַת הַמַּטּוֹת וַחֲצִי הַמַּטֶּה׃
כִּי לָקְחוּ מַטֵּה בְנֵי הָראוּבֵנִי לְבֵית אֲבֹתָם וּמַטֵּה בְנֵי־הַגָּדִי לְבֵית אֲבֹתָם וַחֲצִי מַטֵּה מְנַשֶּׁה לָקְחוּ נַחֲלָתָם׃
שְׁנֵי הַמַּטּוֹת וַחֲצִי הַמַּטֶּה לָקְחוּ נַחֲלָתָם מֵעֵבֶר לְיַרְדֵּן יְרֵחוֹ קֵדְמָה מִזְרָחָה׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
אֵלֶּה שְׁמוֹת הָאֲנָשִׁים אֲשֶׁר־יִנְחֲלוּ לָכֶם אֶת־הָאָרֶץ אֶלְעָזָר הַכֹּהֵן וִיהוֹשֻׁעַ בִּן־נוּן׃
וְנָשִׂיא אֶחָד נָשִׂיא אֶחָד מִמַּטֶּה תִּקְחוּ לִנְחֹל אֶת־הָאָרֶץ׃
וְאֵלֶּה שְׁמוֹת הָאֲנָשִׁים לְמַטֵּה יְהוּדָה כָּלֵב בֶּן־יְפֻנֶּה׃
וּלְמַטֵּה בְּנֵי שִׁמְעוֹן שְׁמוּאֵל בֶּן־עַמִּיהוּד׃
לְמַטֵּה בִנְיָמִן אֱלִידָד בֶּן־כִּסְלוֹן׃
וּלְמַטֵּה בְנֵי־דָן נָשִׂיא בֻּקִּי בֶּן־יָגְלִי׃
לִבְנֵי יוֹסֵף לְמַטֵּה בְנֵי־מְנַשֶּׁה נָשִׂיא חַנִּיאֵל בֶּן־אֵפֹד׃
וּלְמַטֵּה בְנֵי־אֶפְרַיִם נָשִׂיא קְמוּאֵל בֶּן־שִׁפְטָן׃
וּלְמַטֵּה בְנֵי־זְבוּלֻן נָשִׂיא אֱלִיצָפָן בֶּן־פַּרְנָךְ׃
וּלְמַטֵּה בְנֵי־יִשָׂשכָר נָשִׂיא פַּלְטִיאֵל בֶּן־עַזָּן׃
וּלְמַטֵּה בְנֵי־אָשֵׁר נָשִׂיא אֲחִיהוּד בֶּן־שְׁלֹמִי׃
וּלְמַטֵּה בְנֵי־נַפְתָּלִי נָשִׂיא פְּדַהְאֵל בֶּן־עַמִּיהוּד׃
אֵלֶּה אֲשֶׁר צִוָּה יְהוָה לְנַחֵל אֶת־בְּנֵי־יִשְׂרָאֵל בְּאֶרֶץ כְּנָעַן׃

Chapter 35

וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה בְּעַרְבֹת מוֹאָב עַל־יַרְדֵּן יְרֵחוֹ לֵאמֹר׃
צַו אֶת־בְּנֵי יִשְׂרָאֵל וְנָתְנוּ לַלְוִיִּם מִנַּחֲלַת אֲחֻזָּתָם עָרִים לָשָׁבֶת וּמִגְרָשׁ לֶעָרִים סְבִיבֹתֵיהֶם תִּתְּנוּ לַלְוִיִּם׃
וְהָיוּ הֶעָרִים לָהֶם לָשָׁבֶת וּמִגְרְשֵׁיהֶם יִהְיוּ לִבְהֶמְתָּם וְלִרְכֻשָׁם וּלְכֹל חַיָּתָם׃
וּמִגְרְשֵׁי הֶעָרִים אֲשֶׁר תִּתְּנוּ לַלְוִיִּם מִקִּיר הָעִיר וָחוּצָה אֶלֶף אַמָּה סָבִיב׃
וּמַדֹּתֶם מִחוּץ לָעִיר אֶת־פְּאַת־קֵדְמָה אַלְפַּיִם בָּאַמָּה וְאֶת־פְּאַת־נֶגֶב אַלְפַּיִם בָּאַמָּה וְאֶת־פְּאַת־יָם אַלְפַּיִם בָּאַמָּה וְאֵת פְּאַת צָפוֹן אַלְפַּיִם בָּאַמָּה וְהָעִיר בַּתָּוֶךְ זֶה יִהְיֶה לָהֶם מִגְרְשֵׁי הֶעָרִים׃
וְאֵת הֶעָרִים אֲשֶׁר תִּתְּנוּ לַלְוִיִּם אֵת שֵׁשׁ־עָרֵי הַמִּקְלָט אֲשֶׁר תִּתְּנוּ לָנֻס שָׁמָּה הָרֹצֵחַ וַעֲלֵיהֶם תִּתְּנוּ אַרְבָּעִים וּשְׁתַּיִם עִיר׃
כָּל־הֶעָרִים אֲשֶׁר תִּתְּנוּ לַלְוִיִּם אַרְבָּעִים וּשְׁמֹנֶה עִיר אֶתְהֶן וְאֶת־מִגְרְשֵׁיהֶן׃
וְהֶעָרִים אֲשֶׁר תִּתְּנוּ מֵאֲחֻזַּת בְּנֵי־יִשְׂרָאֵל מֵאֵת הָרַב תַּרְבּוּ וּמֵאֵת הַמְעַט תַּמְעִיטוּ אִישׁ כְּפִי נַחֲלָתוֹ אֲשֶׁר יִנְחָלוּ יִתֵּן מֵעָרָיו לַלְוִיִּם׃
וַיְדַבֵּר יְהוָה אֶל־מֹשֶׁה לֵּאמֹר׃
דַּבֵּר אֶל־בְּנֵי יִשְׂרָאֵל וְאָמַרְתָּ אֲלֵהֶם כִּי אַתֶּם עֹבְרִים אֶת־הַיַּרְדֵּן אַרְצָה כְּנָעַן׃
וְהִקְרִיתֶם לָכֶם עָרִים עָרֵי מִקְלָט תִּהְיֶינָה לָכֶם וְנָס שָׁמָּה רֹצֵחַ מַכֵּה־נֶפֶשׁ בִּשְׁגָגָה׃
וְהָיוּ לָכֶם הֶעָרִים לְמִקְלָט מִגֹּאֵל וְלֹא יָמוּת הָרֹצֵחַ עַד־עָמְדוֹ לִפְנֵי הָעֵדָה לַמִּשְׁפָּט׃
וְהֶעָרִים אֲשֶׁר תִּתֵּנוּ שֵׁשׁ־עָרֵי מִקְלָט תִּהְיֶינָה לָכֶם׃
אֵת שְׁלֹשׁ הֶעָרִים תִּתְּנוּ מֵעֵבֶר לַיַּרְדֵּן וְאֵת שְׁלֹשׁ הֶעָרִים תִּתְּנוּ בְּאֶרֶץ כְּנָעַן עָרֵי מִקְלָט תִּהְיֶינָה׃
לִבְנֵי יִשְׂרָאֵל וְלַגֵּר וְלַתּוֹשָׁב בְּתוֹכָם תִּהְיֶינָה שֵׁשׁ־הֶעָרִים הָאֵלֶּה לְמִקְלָט לָנוּס שָׁמָּה כָּל־מַכֵּה־נֶפֶשׁ בִּשְׁגָגָה׃
וְאִם־בִּכְלִי בַרְזֶל הִכָּהוּ וַיָּמֹת רֹצֵחַ הוּא מוֹת יוּמַת הָרֹצֵחַ׃
וְאִם בְּאֶבֶן יָד אֲשֶׁר־יָמוּת בָּהּ הִכָּהוּ וַיָּמֹת רֹצֵחַ הוּא מוֹת יוּמַת הָרֹצֵחַ׃
אוֹ בִּכְלִי עֵץ־יָד אֲשֶׁר־יָמוּת בּוֹ הִכָּהוּ וַיָּמֹת רֹצֵחַ הוּא מוֹת יוּמַת הָרֹצֵחַ׃
גֹּאֵל הַדָּם הוּא יָמִית אֶת־הָרֹצֵחַ בְּפִגְעוֹ־בוֹ הוּא יְמִיתֶנּוּ׃
וְאִם־בְּשִׂנְאָה יֶהְדָּפֶנּוּ אוֹ־הִשְׁלִיךְ עָלָיו בִּצְדִיָּה וַיָּמֹת׃
אוֹ בְאֵיבָה הִכָּהוּ בְיָדוֹ וַיָּמֹת מוֹת־יוּמַת הַמַּכֶּה רֹצֵחַ הוּא גֹּאֵל הַדָּם יָמִית אֶת־הָרֹצֵחַ בְּפִגְעוֹ־בוֹ׃
וְאִם־בְּפֶתַע בְּלֹא־אֵיבָה הֲדָפוֹ אוֹ־הִשְׁלִיךְ עָלָיו כָּל־כְּלִי בְּלֹא צְדִיָּה׃
אוֹ בְכָל־אֶבֶן אֲשֶׁר־יָמוּת בָּהּ בְּלֹא רְאוֹת וַיַּפֵּל עָלָיו וַיָּמֹת וְהוּא לֹא־אוֹיֵב לוֹ וְלֹא מְבַקֵּשׁ רָעָתוֹ׃
וְשָׁפְטוּ הָעֵדָה בֵּין הַמַּכֶּה וּבֵין גֹּאֵל הַדָּם עַל הַמִּשְׁפָּטִים הָאֵלֶּה׃
וְהִצִּילוּ הָעֵדָה אֶת־הָרֹצֵחַ מִיַּד גֹּאֵל הַדָּם וְהֵשִׁיבוּ אֹתוֹ הָעֵדָה אֶל־עִיר מִקְלָטוֹ אֲשֶׁר־נָס שָׁמָּה וְיָשַׁב בָּהּ עַד־מוֹת הַכֹּהֵן הַגָּדֹל אֲשֶׁר־מָשַׁח אֹתוֹ בְּשֶׁמֶן הַקֹּדֶשׁ׃
וְאִם־יָצֹא יֵצֵא הָרֹצֵחַ אֶת־גְּבוּל עִיר מִקְלָטוֹ אֲשֶׁר יָנוּס שָׁמָּה׃
וּמָצָא אֹתוֹ גֹּאֵל הַדָּם מִחוּץ לִגְבוּל עִיר מִקְלָטוֹ וְרָצַח גֹּאֵל הַדָּם אֶת־הָרֹצֵחַ אֵין לוֹ דָּם׃
כִּי בְעִיר מִקְלָטוֹ יֵשֵׁב עַד־מוֹת הַכֹּהֵן הַגָּדֹל וְאַחֲרֵי מוֹת הַכֹּהֵן הַגָּדֹל יָשׁוּב הָרֹצֵחַ אֶל־אֶרֶץ אֲחֻזָּתוֹ׃
וְהָיוּ אֵלֶּה לָכֶם לְחֻקַּת מִשְׁפָּט לְדֹרֹתֵיכֶם בְּכֹל מוֹשְׁבֹתֵיכֶם׃
כָּל־מַכֵּה־נֶפֶשׁ לְפִי עֵדִים יִרְצַח אֶת־הָרֹצֵחַ וְעֵד אֶחָד לֹא־יַעֲנֶה בְנֶפֶשׁ לָמוּת׃
וְלֹא־תִקְחוּ כֹפֶר לְנֶפֶשׁ רֹצֵחַ אֲשֶׁר־הוּא רָשָׁע לָמוּת כִּי־מוֹת יוּמָת׃
וְלֹא־תִקְחוּ כֹפֶר לָנוּס אֶל־עִיר מִקְלָטוֹ לָשׁוּב לָשֶׁבֶת בָּאָרֶץ עַד־מוֹת הַכֹּהֵן׃
וְלֹא־תַחֲנִיפוּ אֶת־הָאָרֶץ אֲשֶׁר אַתֶּם בָּהּ כִּי הַדָּם הוּא יַחֲנִיף אֶת־הָאָרֶץ וְלָאָרֶץ לֹא־יְכֻפַּר לַדָּם אֲשֶׁר שֻׁפַּךְ־בָּהּ כִּי־אִם בְּדַם שֹׁפְכוֹ׃
וְלֹא תְטַמֵּא אֶת־הָאָרֶץ אֲשֶׁר אַתֶּם יֹשְׁבִים בָּהּ אֲשֶׁר אֲנִי שֹׁכֵן בְּתוֹכָהּ כִּי אֲנִי יְהוָה שֹׁכֵן בְּתוֹךְ בְּנֵי יִשְׂרָאֵל׃

Chapter 36

וַיִּקְרְבוּ רָאשֵׁי הָאָבוֹת לְמִשְׁפַּחַת בְּנֵי־גִלְעָד בֶּן־מָכִיר בֶּן־מְנַשֶּׁה מִמִּשְׁפְּחֹת בְּנֵי יוֹסֵף וַיְדַבְּרוּ לִפְנֵי מֹשֶׁה וְלִפְנֵי הַנְּשִׂאִים רָאשֵׁי אָבוֹת לִבְנֵי יִשְׂרָאֵל׃
וַיֹּאמְרוּ אֶת־אֲדֹנִי צִוָּה יְהוָה לָתֵת אֶת־הָאָרֶץ בְּנַחֲלָה בְּגוֹרָל לִבְנֵי יִשְׂרָאֵל וַאדֹנִי צֻוָּה בַיהוָה לָתֵת אֶת־נַחֲלַת צְלָפְחָד אָחִינוּ לִבְנֹתָיו׃
וְהָיוּ לְאֶחָד מִבְּנֵי שִׁבְטֵי בְנֵי־יִשְׂרָאֵל לְנָשִׁים וְנִגְרְעָה נַחֲלָתָן מִנַּחֲלַת אֲבֹתֵינוּ וְנוֹסַף עַל נַחֲלַת הַמַּטֶּה אֲשֶׁר תִּהְיֶינָה לָהֶם וּמִגֹּרַל נַחֲלָתֵנוּ יִגָּרֵעַ׃
וְאִם־יִהְיֶה הַיֹּבֵל לִבְנֵי יִשְׂרָאֵל וְנוֹסְפָה נַחֲלָתָן עַל נַחֲלַת הַמַּטֶּה אֲשֶׁר תִּהְיֶינָה לָהֶם וּמִנַּחֲלַת מַטֵּה אֲבֹתֵינוּ יִגָּרַע נַחֲלָתָן׃
וַיְצַו מֹשֶׁה אֶת־בְּנֵי יִשְׂרָאֵל עַל־פִּי יְהוָה לֵאמֹר כֵּן מַטֵּה בְנֵי־יוֹסֵף דֹּבְרִים׃
זֶה הַדָּבָר אֲשֶׁר־צִוָּה יְהוָה לִבְנוֹת צְלָפְחָד לֵאמֹר לַטּוֹב בְּעֵינֵיהֶם תִּהְיֶינָה לְנָשִׁים אַךְ לְמִשְׁפַּחַת מַטֵּה א�