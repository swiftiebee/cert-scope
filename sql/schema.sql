-- CertScope schema version 1. Run in an existing SQL Server 2019 database.
BEGIN TRANSACTION;

SET XACT_ABORT ON;
DECLARE @schemaLock int;
EXEC @schemaLock=sys.sp_getapplock @Resource=N'CertScope.Schema', @LockMode=N'Exclusive', @LockOwner=N'Transaction', @LockTimeout=25000;
IF @schemaLock<0 THROW 51002, N'Не удалось получить блокировку схемы CertScope.', 1;
IF OBJECT_ID(N'dbo.CS_SchemaVersion',N'U') IS NOT NULL
BEGIN
 IF EXISTS(SELECT 1 FROM dbo.CS_SchemaVersion WHERE Version<>1) THROW 51003, N'Неподдерживаемая версия схемы CertScope.',1;
END;
IF OBJECT_ID(N'dbo.CS_SchemaVersion',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_Certificates',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_CertificateVariants',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_SerialVariants',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_SerialConflicts',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_Locations',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_Observations',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_SourceReports',N'U') IS NULL OR OBJECT_ID(N'dbo.CS_AppliedEvents',N'U') IS NULL
BEGIN
 IF ISNULL(HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','CREATE TABLE'),0)<>1 OR ISNULL(HAS_PERMS_BY_NAME(N'dbo','SCHEMA','ALTER'),0)<>1
  THROW 51004,N'Для первичной миграции нужны CREATE TABLE в базе и ALTER схемы dbo. Администратор может применить sql/schema.sql заранее.',1;
END;
IF OBJECT_ID(N'dbo.CS_SchemaVersion',N'U') IS NULL
 CREATE TABLE dbo.CS_SchemaVersion(Version int NOT NULL CONSTRAINT PK_CS_SchemaVersion PRIMARY KEY, AppliedUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_CertificateVariants',N'U') IS NULL
 CREATE TABLE dbo.CS_CertificateVariants(Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_CS_CertificateVariants PRIMARY KEY, Der varbinary(max) NOT NULL,OwnerName nvarchar(max) NOT NULL,Subject nvarchar(max) NOT NULL,Issuer nvarchar(max) NOT NULL,NotBeforeUtc datetime2(7) NOT NULL,NotAfterUtc datetime2(7) NOT NULL,LicenseStatus nvarchar(max) NOT NULL,LicenseVersion nvarchar(max) NOT NULL, MetadataJson nvarchar(max) NOT NULL, CreatedUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_Certificates',N'U') IS NULL
 CREATE TABLE dbo.CS_Certificates(SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_CS_Certificates PRIMARY KEY NONCLUSTERED, CanonicalSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Certificates_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),CreatedUtc datetime2(7) NOT NULL,UpdatedUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_SerialVariants',N'U') IS NULL
 CREATE TABLE dbo.CS_SerialVariants(SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialVariants_Certificate REFERENCES dbo.CS_Certificates(SerialNumber),Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialVariants_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),CONSTRAINT PK_CS_SerialVariants PRIMARY KEY NONCLUSTERED(SerialNumber,Sha256));
IF OBJECT_ID(N'dbo.CS_SerialConflicts',N'U') IS NULL
 CREATE TABLE dbo.CS_SerialConflicts(SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialConflicts_Certificate REFERENCES dbo.CS_Certificates(SerialNumber),CanonicalSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialConflicts_Canonical REFERENCES dbo.CS_CertificateVariants(Sha256),IncomingSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_SerialConflicts_Incoming REFERENCES dbo.CS_CertificateVariants(Sha256),DetectedUtc datetime2(7) NOT NULL,CONSTRAINT PK_CS_SerialConflicts PRIMARY KEY NONCLUSTERED(SerialNumber,IncomingSha256));
IF OBJECT_ID(N'dbo.CS_Locations',N'U') IS NULL
 CREATE TABLE dbo.CS_Locations(LocationKey char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT PK_CS_Locations PRIMARY KEY,Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Locations_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),Computer nvarchar(255) NOT NULL,Source nvarchar(max) NOT NULL,UserSid nvarchar(256) NOT NULL,RegistryView nvarchar(32) NOT NULL,FirstSeenUtc datetime2(7) NOT NULL,LastSeenUtc datetime2(7) NOT NULL);
IF OBJECT_ID(N'dbo.CS_Observations',N'U') IS NULL
 CREATE TABLE dbo.CS_Observations(EventId uniqueidentifier NOT NULL CONSTRAINT PK_CS_Observations PRIMARY KEY,ScanId uniqueidentifier NOT NULL,SerialNumber nvarchar(512) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Observations_Certificate REFERENCES dbo.CS_Certificates(SerialNumber),Sha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Observations_Variant REFERENCES dbo.CS_CertificateVariants(Sha256),LocationKey char(64) COLLATE Latin1_General_100_BIN2 NOT NULL CONSTRAINT FK_CS_Observations_Location REFERENCES dbo.CS_Locations(LocationKey),FoundUtc datetime2(7) NOT NULL,PayloadJson nvarchar(max) NOT NULL);
IF OBJECT_ID(N'dbo.CS_SourceReports',N'U') IS NULL
 CREATE TABLE dbo.CS_SourceReports(EventId uniqueidentifier NOT NULL CONSTRAINT PK_CS_SourceReports PRIMARY KEY,ScanId uniqueidentifier NOT NULL,Computer nvarchar(255) NOT NULL,Source nvarchar(max) NOT NULL,Status nvarchar(64) NOT NULL,PayloadJson nvarchar(max) NOT NULL);
IF OBJECT_ID(N'dbo.CS_AppliedEvents',N'U') IS NULL
 CREATE TABLE dbo.CS_AppliedEvents(EventId uniqueidentifier NOT NULL CONSTRAINT PK_CS_AppliedEvents PRIMARY KEY,EventKind char(1) NOT NULL,PayloadSha256 char(64) COLLATE Latin1_General_100_BIN2 NOT NULL,AppliedUtc datetime2(7) NOT NULL);
IF NOT EXISTS(SELECT 1 FROM dbo.CS_SchemaVersion) INSERT dbo.CS_SchemaVersion(Version,AppliedUtc) VALUES(1,SYSUTCDATETIME());

COMMIT;