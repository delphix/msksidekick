# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)

## [Unreleased]

## [1.0.0] - 2020-07-27
### Added
- First Version
- Support for load balancing Masking Jobs across masking engine pool
- Support for sync of engine
- Support for sync of environment
- Support for sync of job

## [1.0.0] - 2020-07-30
### Added
- Compiled using python 3.8.5 version

## [1.0.1] - 2020-08-04
### Added
- Added support for https protocol
- Added Version Info

## [1.0.2] - 2020-08-12
### Added
- Bugfix : Added support for https protocol to VE
- Bugfix : On the fly masking for mainframe expects source_env_id. Added source_env_id

## [1.0.4] - 2020-08-24
### Added
- Bugfix : Added support for cpu using dx_toolkit to handle encrypted passwords

## [1.0.5] - 2020-08-24
### Added
- Bugfix : Capture CPU does not account CRITICAL AND WARNING CPU data

## [1.0.6] - 2020-09-01
### Added
- Feature : Added support to sync environment with on the fly masking jobs
- Bugfix  : Provide user friendly message if job does not exists in any engine 
- BufFix  : Set cpu as 0 if not able to connect VE mgmt stack and proceed

## [1.1.0] - 2020-09-03
### Added
- Feature : Added support to backup / restore engine objects to / from filesystem

## [1.1.1] - 2020-09-09
### Added
- Feature : Added support to adjust OTF connector when restoring from backup files

## [1.1.2] - 2020-10-05
### Added
- Feature : Added support to cleanup extra environment and application from target engine during sync engine
- Bugfix  : Only non-default Algorithm, Domain , Profile are deleted during cleanup.
- Bugfix  : Handle file connectors for OTF jobs while adjusting connectors

## [1.1.3] - 2020-11-01
### Added
- Feature : Added Roles/Users to be synced during Engine sync
- Bugfix  : Handle mainframe dataset fileformat cleanup.
- Bugfix  : Handle mainframe dataset fileformat sync.
- Feature : Added module to test all connectors at a time

## [1.1.4] - 2021-19-01
### Added
- Feature : Added support for queueing job on engine >= 6.0.5 when all engines are red

## [1.1.5] - 2021-19-01
### Added
- Bugfix : Display correct message as job queued when all engines are busy
- Feature: Pull all running job list from all engine pools