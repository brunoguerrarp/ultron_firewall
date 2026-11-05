export namespace main {
	
	export class UIState {
	    running: boolean;
	    engineError: string;
	    needsSetup: boolean;
	    unlocked: boolean;
	    promptEnabled: boolean;
	    enabled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UIState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.engineError = source["engineError"];
	        this.needsSetup = source["needsSetup"];
	        this.unlocked = source["unlocked"];
	        this.promptEnabled = source["promptEnabled"];
	        this.enabled = source["enabled"];
	    }
	}

}

export namespace model {
	
	export class Config {
	    enabled: boolean;
	    promptEnabled: boolean;
	    notifyEnabled: boolean;
	    interceptUdp: boolean;
	    defaultOutbound: string;
	    defaultInbound: string;
	    promptTimeoutSecs: number;
	    reportEnabled: boolean;
	    reportUrl: string;
	    reportToken: string;
	    blocklist: string[];
	    allowedDomains: string[];
	    detectInbound: boolean;
	    detectScan: boolean;
	    detectBlocklist: boolean;
	    detectOutDenied: boolean;
	    scanWindowSecs: number;
	    scanPortThreshold: number;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.promptEnabled = source["promptEnabled"];
	        this.notifyEnabled = source["notifyEnabled"];
	        this.interceptUdp = source["interceptUdp"];
	        this.defaultOutbound = source["defaultOutbound"];
	        this.defaultInbound = source["defaultInbound"];
	        this.promptTimeoutSecs = source["promptTimeoutSecs"];
	        this.reportEnabled = source["reportEnabled"];
	        this.reportUrl = source["reportUrl"];
	        this.reportToken = source["reportToken"];
	        this.blocklist = source["blocklist"];
	        this.allowedDomains = source["allowedDomains"];
	        this.detectInbound = source["detectInbound"];
	        this.detectScan = source["detectScan"];
	        this.detectBlocklist = source["detectBlocklist"];
	        this.detectOutDenied = source["detectOutDenied"];
	        this.scanWindowSecs = source["scanWindowSecs"];
	        this.scanPortThreshold = source["scanPortThreshold"];
	    }
	}
	export class Connection {
	    id: string;
	    // Go type: time
	    time: any;
	    direction: string;
	    protocol: string;
	    pid: number;
	    processPath: string;
	    processName: string;
	    localIp: string;
	    localPort: number;
	    remoteIp: string;
	    remotePort: number;
	    remoteHost: string;
	    service: string;
	
	    static createFrom(source: any = {}) {
	        return new Connection(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.time = this.convertValues(source["time"], null);
	        this.direction = source["direction"];
	        this.protocol = source["protocol"];
	        this.pid = source["pid"];
	        this.processPath = source["processPath"];
	        this.processName = source["processName"];
	        this.localIp = source["localIp"];
	        this.localPort = source["localPort"];
	        this.remoteIp = source["remoteIp"];
	        this.remotePort = source["remotePort"];
	        this.remoteHost = source["remoteHost"];
	        this.service = source["service"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class HistoryEntry {
	    id: string;
	    // Go type: time
	    time: any;
	    direction: string;
	    protocol: string;
	    pid: number;
	    processPath: string;
	    processName: string;
	    localIp: string;
	    localPort: number;
	    remoteIp: string;
	    remotePort: number;
	    remoteHost: string;
	    service: string;
	    decision: string;
	    ruleMatch: string;
	    threat: boolean;
	    threatKind: string;
	    severity: string;
	
	    static createFrom(source: any = {}) {
	        return new HistoryEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.time = this.convertValues(source["time"], null);
	        this.direction = source["direction"];
	        this.protocol = source["protocol"];
	        this.pid = source["pid"];
	        this.processPath = source["processPath"];
	        this.processName = source["processName"];
	        this.localIp = source["localIp"];
	        this.localPort = source["localPort"];
	        this.remoteIp = source["remoteIp"];
	        this.remotePort = source["remotePort"];
	        this.remoteHost = source["remoteHost"];
	        this.service = source["service"];
	        this.decision = source["decision"];
	        this.ruleMatch = source["ruleMatch"];
	        this.threat = source["threat"];
	        this.threatKind = source["threatKind"];
	        this.severity = source["severity"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Rule {
	    id: string;
	    enabled: boolean;
	    processPath: string;
	    remoteIp: string;
	    remotePort: number;
	    direction: string;
	    action: string;
	    // Go type: time
	    created: any;
	    note: string;
	
	    static createFrom(source: any = {}) {
	        return new Rule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.enabled = source["enabled"];
	        this.processPath = source["processPath"];
	        this.remoteIp = source["remoteIp"];
	        this.remotePort = source["remotePort"];
	        this.direction = source["direction"];
	        this.action = source["action"];
	        this.created = this.convertValues(source["created"], null);
	        this.note = source["note"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

