function parseIPv4(ip) {
    const octets = ip.trim().split('.');
    if (octets.length !== 4) throw new Error('Invalid IPv4 format');
    const nums = octets.map(o => {
      const n = Number(o);
      if (isNaN(n) || n < 0 || n > 255) throw new Error('Each octet must be 0–255');
      return n;
    });
    const ipInt = ((nums[0] << 24) >>> 0) + (nums[1] << 16) + (nums[2] << 8) + nums[3];
    return { nums, int: ipInt };
  }
  
  function intToIp(int) {
    return [
      (int >>> 24) & 255,
      (int >>> 16) & 255,
      (int >>> 8) & 255,
      int & 255
    ].join('.');
  }
  
  function parseMask(cidr) {
    const num = Number(cidr);
    if (isNaN(num) || num < 0 || num > 32) throw new Error('CIDR must be between 0 and 32');
    const maskInt = num === 0 ? 0 : (0xFFFFFFFF << (32 - num)) >>> 0;
    return { maskInt, cidr: num };
  }
  
  function maskToStrings(maskInt, cidr) {
    const dotted = intToIp(maskInt);
    const binary = Array.from({ length: 32 }, (_, i) =>
      (maskInt >>> (31 - i)) & 1
    ).join('').replace(/(.{8})/g, '$1.').slice(0, -1);
    return { dotted, binary };
  }
  
  function calcSubnet(ipInt, maskInt, cidr) {
    const network = ipInt & maskInt;
    const broadcast = (network | (~maskInt >>> 0)) >>> 0;
    const hostBits = 32 - cidr;
    let usableHosts = 0, firstHost = 0, lastHost = 0;
  
    if (cidr === 31) {
      usableHosts = 2;
      firstHost = network;
      lastHost = broadcast;
    } else if (cidr === 32) {
      usableHosts = 1;
      firstHost = lastHost = network;
    } else {
      usableHosts = Math.max(0, Math.pow(2, hostBits) - 2);
      firstHost = usableHosts > 0 ? network + 1 : network;
      lastHost = usableHosts > 0 ? broadcast - 1 : broadcast;
    }
  
    return { network, broadcast, usableHosts, firstHost, lastHost };
  }
  
  function isPrivate(ipInt) {
    const a = (ipInt >>> 24) & 255;
    const b = (ipInt >>> 16) & 255;
    return (
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }
  
  function getClass(firstOctet) {
    if (firstOctet < 128) return 'Class A';
    if (firstOctet < 192) return 'Class B';
    if (firstOctet < 224) return 'Class C';
    if (firstOctet < 240) return 'Class D';
    return 'Class E';
  }
  
  document.getElementById('calcBtn').addEventListener('click', () => {
    const ipInput = document.getElementById('ip').value.trim();
    const cidrInput = document.getElementById('cidr').value.trim();
    const errorBox = document.getElementById('error');
  
    errorBox.textContent = '';
  
    try {
      if (!ipInput || !cidrInput) throw new Error('Please enter both IP and CIDR');
  
      const { nums, int: ipInt } = parseIPv4(ipInput);
      const { maskInt, cidr } = parseMask(cidrInput);
      const { dotted, binary } = maskToStrings(maskInt, cidr);
      const { network, broadcast, usableHosts, firstHost, lastHost } = calcSubnet(ipInt, maskInt, cidr);
  
      const firstOctet = nums[0];
      const addrClass = getClass(firstOctet);
      const privType = isPrivate(ipInt) ? 'Private' : 'Public';
  
      document.getElementById('network').value = intToIp(network);
      document.getElementById('broadcast').value = intToIp(broadcast);
      document.getElementById('mask-decimal').value = dotted;
      document.getElementById('mask-binary').value = binary;
      document.getElementById('hosts').value = usableHosts;
      document.getElementById('class').value = addrClass;
      document.getElementById('type').value = privType;
      document.getElementById('range').value = `${intToIp(firstHost)} – ${intToIp(lastHost)}`;
    } catch (err) {
      errorBox.textContent = err.message;
      clearResults();
    }
  });
  
  function clearResults() {
    const ids = [
      'network', 'broadcast', 'mask-decimal', 'mask-binary',
      'hosts', 'class', 'type', 'range'
    ];
    ids.forEach(id => document.getElementById(id).value = '');
  }