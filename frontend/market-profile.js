(function () {
  const MARKET_STORAGE_KEY = 'kansa_market';
  const SUPPORTED_MARKETS = ['port', 'rental'];

  const RENTAL_REPLACEMENTS = {
    ja: [
      ['Container Log', '入退去写真記録'],
      ['港湾・物流', '賃貸管理・原状回復'],
      ['コンテナ番号', '物件・部屋'],
      ['コンテナ', '物件'],
      ['搬入時点', '入居時点'],
      ['搬入時', '入居時'],
      ['搬出時', '退去時'],
      ['搬入', '入居時'],
      ['搬出', '退去時'],
      ['シール', '設備'],
      ['損傷', '傷・汚れ'],
    ],
    en: [
      ['Container Log', 'Move-in / Move-out Photo Log'],
      ['container number', 'property / unit'],
      ['Container number', 'Property / unit'],
      ['containers', 'properties'],
      ['Containers', 'Properties'],
      ['container', 'property'],
      ['Container', 'Property'],
      ['Gate in', 'Move-in'],
      ['Gate out', 'Move-out'],
      ['Seal', 'Equipment'],
      ['Damage', 'Damage / wear'],
    ],
    'zh-CN': [
      ['集装箱编号', '房源・房间'],
      ['集装箱', '房源'],
      ['进场', '入住时'],
      ['出场', '退租时'],
      ['铅封', '设备'],
      ['损伤', '损伤・污渍'],
    ],
    vi: [
      ['số container', 'bất động sản / phòng'],
      ['Số container', 'Bất động sản / phòng'],
      ['container', 'bất động sản'],
      ['Container', 'Bất động sản'],
      ['nhập bãi', 'khi nhận nhà'],
      ['xuất bãi', 'khi trả nhà'],
      ['seal', 'thiết bị'],
      ['hư hỏng', 'hư hỏng / vết bẩn'],
    ],
  };

  function normalizeMarket(raw) {
    const value = String(raw || '').trim().toLowerCase();
    if (value === 'rental' || value === 'lease' || value === 'property') return 'rental';
    if (value === 'port' || value === 'container') return 'port';
    return '';
  }

  function detectMarket() {
    const params = new URLSearchParams(window.location.search);
    const requested = normalizeMarket(params.get('market'));
    if (requested) {
      window.localStorage.setItem(MARKET_STORAGE_KEY, requested);
      return requested;
    }
    const stored = normalizeMarket(window.localStorage.getItem(MARKET_STORAGE_KEY));
    if (stored) return stored;
    return normalizeMarket(window.KANSA_CONFIG?.market) || 'port';
  }

  const currentMarket = detectMarket();

  function replaceText(value, replacements) {
    return (replacements || []).reduce(
      (result, [from, to]) => result.split(from).join(to),
      String(value || '')
    );
  }

  function translate(_original, language, translated) {
    if (currentMarket !== 'rental') return translated;
    const rules = RENTAL_REPLACEMENTS[language] || RENTAL_REPLACEMENTS.ja;
    return replaceText(translated, rules);
  }

  function updateMarketQuery(nextMarket) {
    const normalized = normalizeMarket(nextMarket);
    if (!SUPPORTED_MARKETS.includes(normalized)) return;
    window.localStorage.setItem(MARKET_STORAGE_KEY, normalized);
    const url = new URL(window.location.href);
    url.searchParams.set('market', normalized);
    window.location.assign(url.toString());
  }

  function applyMarket() {
    document.documentElement.dataset.market = currentMarket;
    const selector = document.querySelector('#market-mode-select');
    if (selector) {
      selector.value = currentMarket;
      selector.addEventListener('change', (event) => updateMarketQuery(event.target.value), { once: true });
    }
    const folderTitle = document.querySelector('#folder-title');
    if (folderTitle) {
      folderTitle.placeholder = currentMarket === 'rental' ? '例：桜町マンション 203号室' : 'TCLU1234567';
    }
  }

  window.KANSA_MARKET = {
    id: currentMarket,
    isRental: currentMarket === 'rental',
    supportedMarkets: SUPPORTED_MARKETS.slice(),
    translate,
    apply: applyMarket,
    select: updateMarketQuery,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyMarket, { once: true });
  } else {
    applyMarket();
  }
})();
