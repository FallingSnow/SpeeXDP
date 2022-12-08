#[derive(Debug, Clone, Copy)]
struct BTree<K, V, const S: usize>([Leaf<K, V>; S]);

#[derive(Debug, Clone, Copy)]
struct Leaf<K, V> {
    key: K,
    value: V
}

#[cfg(feature = "userspace")]
unsafe impl<K: Copy + 'static, V: Copy + 'static, const S: usize> aya::Pod for BTree<K, V, S> {}

impl<K, V, const S: usize> BTree<K, V, S> {
    pub fn get(key: K) {
        
    }
}