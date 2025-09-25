import {
    Address,
    beginCell,
    Cell,
    Contract,
    contractAddress,
    ContractProvider,
    Sender,
    SendMode
} from '@ton/core';

export type NftRentExtConfig = {
    wallet: Address;
    beneficiary: Address;
    nft: Address;
    publicKey: bigint;
    amount: bigint;
    period: number;
    start_time: number;
    last_payment_time: number;
    is_paid: number;
    ext_nonce: number;
    failed_attempts: number;
};

export function nftRentConfigToCell(config: NftRentExtConfig): Cell {
    return beginCell()
        // initial mode: not_init (1) as per contract
        .storeUint(1, 2)
        .storeAddress(config.wallet)
        .storeAddress(config.beneficiary)
        .storeAddress(config.nft)
        .storeCoins(config.amount)
        .storeUint(config.period, 32)
        .storeUint(config.start_time, 32)
        .storeUint(config.last_payment_time, 32)
        .storeUint(config.is_paid, 1)
        .storeUint(config.ext_nonce, 32)
        .storeUint(config.failed_attempts, 8)
        // store public key in a ref to avoid root cell overflow
        .storeRef(beginCell().storeUint(config.publicKey, 256).endCell())
        .endCell();
}

export const RentOpcodes = {
    payment_request: 0x22de8175,
    extension_action: 0x6578746E,
    proxy_send: 0x6bdc56b3,
};

export class NftRentExt implements Contract {
    constructor(readonly address: Address, readonly init?: { code: Cell; data: Cell }) { }

    static createFromAddress(address: Address) {
        return new NftRentExt(address);
    }

    static createFromConfig(config: NftRentExtConfig, code: Cell, workchain = 0) {
        const data = nftRentConfigToCell(config);
        const init = { code, data };
        return new NftRentExt(contractAddress(workchain, init), init);
    }

    async sendDeploy(provider: ContractProvider, via: Sender, value: bigint, relayBody?: Cell) {
        await provider.internal(via, {
            value,
            sendMode: SendMode.PAY_GAS_SEPARATELY,
            body: relayBody ? beginCell().storeRef(relayBody).endCell() : beginCell().endCell()
        });
    }

    async sendExternalSignedMessage(provider: ContractProvider, body: Cell) {
        return provider.external(body);
    }

    async sendExternalForRequestPayment(provider: ContractProvider, _via: Sender) {
        return provider.external(beginCell().endCell());
    }

    async getRentData(provider: ContractProvider) {
        const result = (await provider.get('get_rent_data', [])).stack;
        const wallet = result.readAddress();
        const beneficiary = result.readAddress();
        const nft = result.readAddress();
        const amount = result.readBigNumber();
        const period = result.readNumber();
        const start_time = result.readNumber();
        const last_payment_time = result.readNumber();
        const is_paid = result.readNumber();
        const active = result.readNumber();
        return { wallet, beneficiary, nft, amount, period, start_time, last_payment_time, is_paid, active };
    }

    async getFailedAttempts(provider: ContractProvider) {
        const result = (await provider.get('get_failed_attempts', [])).stack;
        return result.readNumber();
    }

    async getExtNonce(provider: ContractProvider) {
        const result = (await provider.get('get_ext_nonce', [])).stack;
        return result.readNumber();
    }
}


