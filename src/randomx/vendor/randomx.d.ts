export type RxCacheHandle = {
	memory: WebAssembly.Memory;
	thunk: WebAssembly.Module;
	vm: WebAssembly.Module;
};
export declare class RxCache {
	get shared(): boolean;
	get handle(): RxCacheHandle;
}
export type RxCacheOptions = {
	shared?: boolean;
};
export declare function randomx_init_cache(K: string | Uint8Array | undefined | null, cache: RxCache): RxCache;
export declare function randomx_init_cache(K?: string | Uint8Array | undefined | null, conf?: RxCacheOptions | undefined | null): RxCache;
export type RxSuperscalarHash = (item_index: bigint) => [
	bigint,
	bigint,
	bigint,
	bigint,
	bigint,
	bigint,
	bigint,
	bigint
];
export declare function randomx_superscalarhash(cache: RxCache | RxCacheHandle): RxSuperscalarHash;
export declare function randomx_machine_id(): string;
export declare function randomx_create_vm(cache: RxCache | RxCacheHandle): {
	calculate_hash(H: Uint8Array | string): Uint8Array;
	calculate_hex_hash(H: Uint8Array | string): string;
};

export {};
