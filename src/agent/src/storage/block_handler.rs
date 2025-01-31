// Copyright (c) 2019 Ant Financial
// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use kata_types::device::{
    DRIVER_BLK_CCW_TYPE, DRIVER_BLK_MMIO_TYPE, DRIVER_BLK_PCI_TYPE, DRIVER_NVDIMM_TYPE,
    DRIVER_SCSI_TYPE,
};
use kata_types::mount::StorageDevice;
use protocols::agent::Storage;
use tracing::instrument;

#[cfg(target_arch = "s390x")]
use crate::ccw;
#[cfg(target_arch = "s390x")]
use crate::device::block_device_handler::get_virtio_blk_ccw_device_name;
use crate::device::block_device_handler::{
    get_virtio_blk_mmio_device_name, get_virtio_blk_pci_device_name,
};
use crate::device::nvdimm_device_handler::wait_for_pmem_device;
use crate::device::scsi_device_handler::get_scsi_device_name;
use crate::pci;
use crate::storage::{common_storage_handler, new_device, StorageContext, StorageHandler};

#[derive(Debug)]
pub struct VirtioBlkMmioHandler {}

impl VirtioBlkMmioHandler {
    pub async fn update_device_path(
        storage: &mut Storage,
        ctx: &mut StorageContext<'_>,
    ) -> Result<()> {
        if !Path::new(&storage.source).exists() {
            get_virtio_blk_mmio_device_name(ctx.sandbox, &storage.source)
                .await
                .context("failed to get mmio device name")?;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageHandler for VirtioBlkMmioHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_MMIO_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Self::update_device_path(&mut storage, ctx).await?;
        let path = common_storage_handler(ctx.logger, &storage)?;
        new_device(path)
    }
}

#[derive(Debug)]
pub struct VirtioBlkPciHandler {}

impl VirtioBlkPciHandler {
    pub async fn update_device_path(
        storage: &mut Storage,
        ctx: &mut StorageContext<'_>,
    ) -> Result<()> {
        // If hot-plugged, get the device node path based on the PCI path
        // otherwise use the virt path provided in Storage Source
        if storage.source.starts_with("/dev") {
            let metadata = fs::metadata(&storage.source)
                .context(format!("get metadata on file {:?}", &storage.source))?;
            let mode = metadata.permissions().mode();
            if mode & libc::S_IFBLK == 0 {
                return Err(anyhow!("Invalid device {}", &storage.source));
            }
        } else {
            let pcipath = pci::Path::from_str(&storage.source)?;
            let dev_path = get_virtio_blk_pci_device_name(ctx.sandbox, &pcipath).await?;
            storage.source = dev_path;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageHandler for VirtioBlkPciHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_PCI_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Self::update_device_path(&mut storage, ctx).await?;
        let path = common_storage_handler(ctx.logger, &storage)?;
        new_device(path)
    }
}

#[derive(Debug)]
pub struct VirtioBlkCcwHandler {}

impl VirtioBlkCcwHandler {
    /// Currently this function is only called in dm_verity.rs
    #[cfg(feature = "host-share-image-block")]
    pub async fn update_device_path(
        _storage: &mut Storage,
        _ctx: &mut StorageContext<'_>,
    ) -> Result<()> {
        #[cfg(target_arch = "s390x")]
        {
            let ccw_device = ccw::Device::from_str(&_storage.source)?;
            let dev_path = get_virtio_blk_ccw_device_name(_ctx.sandbox, &ccw_device).await?;
            _storage.source = dev_path;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageHandler for VirtioBlkCcwHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_BLK_CCW_TYPE]
    }

    #[cfg(target_arch = "s390x")]
    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Self::update_device_path(&mut storage, ctx).await?;
        let path = common_storage_handler(ctx.logger, &storage)?;
        new_device(path)
    }

    #[cfg(not(target_arch = "s390x"))]
    #[instrument]
    async fn create_device(
        &self,
        _storage: Storage,
        _ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Err(anyhow!("CCW is only supported on s390x"))
    }
}

#[derive(Debug)]
pub struct ScsiHandler {}

impl ScsiHandler {
    pub async fn update_device_path(
        storage: &mut Storage,
        ctx: &mut StorageContext<'_>,
    ) -> Result<()> {
        // Retrieve the device path from SCSI address.
        let dev_path = get_scsi_device_name(ctx.sandbox, &storage.source).await?;
        storage.source = dev_path;
        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageHandler for ScsiHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_SCSI_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Self::update_device_path(&mut storage, ctx).await?;
        let path = common_storage_handler(ctx.logger, &storage)?;
        new_device(path)
    }
}

#[derive(Debug)]
pub struct PmemHandler {}

impl PmemHandler {
    pub async fn update_device_path(
        storage: &mut Storage,
        ctx: &mut StorageContext<'_>,
    ) -> Result<()> {
        // Retrieve the device for pmem storage
        wait_for_pmem_device(ctx.sandbox, &storage.source).await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl StorageHandler for PmemHandler {
    #[instrument]
    fn driver_types(&self) -> &[&str] {
        &[DRIVER_NVDIMM_TYPE]
    }

    #[instrument]
    async fn create_device(
        &self,
        mut storage: Storage,
        ctx: &mut StorageContext,
    ) -> Result<Arc<dyn StorageDevice>> {
        Self::update_device_path(&mut storage, ctx).await?;
        let path = common_storage_handler(ctx.logger, &storage)?;
        new_device(path)
    }
}
