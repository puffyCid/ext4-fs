use crate::error::Ext4Error;
use log::error;
use nom::number::complete::{le_u16, le_u32};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) struct Extents {
    signature: u16,
    number_of_extents_or_indexes: u16,
    max_extents_or_indexes: u16,
    pub(crate) depth: u16,
    generation: u32,
    pub(crate) extent_descriptors: Vec<ExtentDescriptor>,
    pub(crate) index_descriptors: Vec<IndexDescriptor>,
    pub(crate) extent_descriptor_list: BTreeMap<u32, ExtentDescriptor>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExtentDescriptor {
    pub(crate) logical_block_number: u32,
    pub(crate) number_of_blocks: u16,
    pub(crate) block_number: u64,
    pub(crate) next_logical_block_number: u32,
    pub(crate) block_diff: u32,
    pub(crate) upper_part_physical_block_number: u16,
    pub(crate) lower_part_physical_block_number: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct IndexDescriptor {
    pub(crate) logical_block_number: u32,
    pub(crate) block_number: u64,
    pub(crate) lower_part_physical_block_number: u32,
    pub(crate) upper_part_physical_block_number: u16,
}

impl Extents {
    /// Read and pars the extents data
    pub(crate) fn read_extents(data: &[u8]) -> Result<Extents, Ext4Error> {
        let extents = match Extents::parse_extents(data) {
            Ok((_, results)) => results,
            Err(err) => {
                error!("[ext4-fs] Could not parse extents {err:?}");
                return Err(Ext4Error::Extents);
            }
        };

        Ok(extents)
    }

    /// Parse the extent bytes
    pub(crate) fn parse_extents(data: &[u8]) -> nom::IResult<&[u8], Extents> {
        let (input, signature) = le_u16(data)?;
        let (input, number_of_extents_or_indexes) = le_u16(input)?;
        let (input, max_extents_or_indexes) = le_u16(input)?;
        let (input, depth) = le_u16(input)?;
        let (mut remaining, generation) = le_u32(input)?;

        let mut extent = Extents {
            signature,
            number_of_extents_or_indexes,
            max_extents_or_indexes,
            depth,
            generation,
            extent_descriptors: Vec::new(),
            index_descriptors: Vec::new(),
            extent_descriptor_list: BTreeMap::new(),
        };
        let mut count = 0;
        // If depth = 0 then we have array of extents. These are the "leafs" of our b-tree. It contains data we want
        // Any other value means we have array of indexes. Which point to more extents
        // The data will be a hash tree: https://github.com/libyal/libfsext/blob/main/documentation/Extended%20File%20System%20(EXT).asciidoc#113-hash-tree-directory-entries
        // https://blogs.oracle.com/linux/post/understanding-ext4-disk-layout-part-2
        while count < number_of_extents_or_indexes {
            count += 1;
            if depth == 0 {
                let (input, logical_block_number) = le_u32(remaining)?;
                let (input, number_of_blocks) = le_u16(input)?;
                let (input, upper_part_physical_block_number) = le_u16(input)?;
                let (input, lower_part_physical_block_number) = le_u32(input)?;
                remaining = input;
                let block_number = (upper_part_physical_block_number as u64) << 32
                    | lower_part_physical_block_number as u64;
                let desc = ExtentDescriptor {
                    logical_block_number,
                    number_of_blocks,
                    upper_part_physical_block_number,
                    lower_part_physical_block_number,
                    next_logical_block_number: 0,
                    block_number,
                    block_diff: 0,
                };
                extent.extent_descriptors.push(desc);
                continue;
            }

            // The extent points to more blocks
            // Will need to parse the extents at the offset: block_number * blocksize
            let (input, logical_block_number) = le_u32(remaining)?;
            let (input, lower_part_physical_block_number) = le_u32(input)?;
            let (input, upper_part_physical_block_number) = le_u16(input)?;
            let (input, _unknown) = le_u16(input)?;
            remaining = input;
            let block_number = (upper_part_physical_block_number as u64) << 32
                | lower_part_physical_block_number as u64;
            let index = IndexDescriptor {
                logical_block_number,
                lower_part_physical_block_number,
                upper_part_physical_block_number,
                block_number,
            };
            extent.index_descriptors.push(index);
        }
        let mut extent_iterator = extent.extent_descriptors.iter_mut().peekable();
        while let Some(value) = extent_iterator.next() {
            if let Some(next_logical_block) = extent_iterator.peek() {
                value.next_logical_block_number = next_logical_block.logical_block_number;
                if value.next_logical_block_number
                    - (value.logical_block_number + value.number_of_blocks as u32)
                    > 0
                {
                    // If the diff is greater than 0.
                    // Then sparse data exists
                    value.block_diff = value.next_logical_block_number
                        - (value.logical_block_number + value.number_of_blocks as u32);
                }
            }
            extent
                .extent_descriptor_list
                .insert(value.logical_block_number, value.clone());
        }

        Ok((input, extent))
    }
}

#[cfg(test)]
mod tests {
    use crate::extents::Extents;

    #[test]
    fn test_parse_extents() {
        let test = [
            10, 243, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let (_, results) = Extents::parse_extents(&test).unwrap();
        assert_eq!(results.number_of_extents_or_indexes, 0);
        assert_eq!(results.max_extents_or_indexes, 4);
    }

    #[test]
    fn test_parse_root_extents() {
        let test = [
            10, 243, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 36, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        let (_, results) = Extents::parse_extents(&test).unwrap();
        assert_eq!(results.number_of_extents_or_indexes, 1);
        assert_eq!(results.max_extents_or_indexes, 4);

        assert_eq!(results.depth, 0);
        assert_eq!(results.extent_descriptor_list.len(), 1);
        assert_eq!(results.extent_descriptors[0].logical_block_number, 0);
        assert_eq!(
            results.extent_descriptors[0].lower_part_physical_block_number,
            9220
        );
        assert_eq!(results.extent_descriptors[0].block_number, 9220);
        assert_eq!(
            results.extent_descriptors[0].upper_part_physical_block_number,
            0
        );
        assert_eq!(results.extent_descriptors[0].number_of_blocks, 1);
    }
}
