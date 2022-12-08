#!/usr/bin/env node

// Usage ./ip-to-32bit.js 192.168.1.1

let lastArg = process.argv[process.argv.length - 1];
let ip = lastArg.split('.');

ip = ip.map(s => BigInt(parseInt(s)));

const converted = (ip[0] << BigInt(24)) + (ip[1] << BigInt(16)) + (ip[2] << BigInt(8)) + ip[3];

process.stdout.write(converted + '\n');
