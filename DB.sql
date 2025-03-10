USE master;
ALTER DATABASE BlogManagement SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
DROP DATABASE IF EXISTS BlogManagement;
GO

-- Tạo database mới
CREATE DATABASE BlogManagement;
GO
USE BlogManagement;
GO

-- Bảng Users
IF OBJECT_ID('Users', 'U') IS NOT NULL DROP TABLE Users;
CREATE TABLE Users (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    Username NVARCHAR(50) UNIQUE NOT NULL,
    Email NVARCHAR(100) UNIQUE NOT NULL,
    PasswordHash NVARCHAR(255) NOT NULL,
    Role NVARCHAR(20) CHECK (Role IN ('Admin', 'Author', 'Reader')) NOT NULL,
    CreatedAt DATETIME DEFAULT GETDATE()
);
GO

-- Bảng Posts
IF OBJECT_ID('Posts', 'U') IS NOT NULL DROP TABLE Posts;
CREATE TABLE Posts (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    AuthorId INT NOT NULL,
    Title NVARCHAR(255) NOT NULL,
    Content TEXT NOT NULL,
    CreatedAt DATETIME DEFAULT GETDATE(),
    UpdatedAt DATETIME DEFAULT GETDATE(),
    Status NVARCHAR(20) CHECK (Status IN ('Draft', 'Published', 'Pending')) DEFAULT 'Pending'
);
GO

-- Bảng Comments (Fix lỗi: Cho phép UserId NULL)
IF OBJECT_ID('Comments', 'U') IS NOT NULL DROP TABLE Comments;
CREATE TABLE Comments (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    PostId INT NOT NULL,
    UserId INT NULL, -- Đổi từ NOT NULL thành NULL
    Content NVARCHAR(1000) NOT NULL,
    CreatedAt DATETIME DEFAULT GETDATE()
);
GO

-- Bảng Likes (Fix lỗi tương tự)
IF OBJECT_ID('Likes', 'U') IS NOT NULL DROP TABLE Likes;
CREATE TABLE Likes (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    PostId INT NOT NULL,
    UserId INT NULL, -- Đổi từ NOT NULL thành NULL
    CreatedAt DATETIME DEFAULT GETDATE()
);
GO

-- Bảng Reports
IF OBJECT_ID('Reports', 'U') IS NOT NULL DROP TABLE Reports;
CREATE TABLE Reports (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    CommentId INT NOT NULL,
    ReportedBy INT NULL, -- Fix lỗi tương tự
    Reason NVARCHAR(500) NOT NULL,
    CreatedAt DATETIME DEFAULT GETDATE()
);
GO

-- Bảng FavoritePosts
IF OBJECT_ID('FavoritePosts', 'U') IS NOT NULL DROP TABLE FavoritePosts;
CREATE TABLE FavoritePosts (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    UserId INT NOT NULL,
    PostId INT NOT NULL,
    CreatedAt DATETIME DEFAULT GETDATE()
);
GO

-- Bảng Notifications
IF OBJECT_ID('Notifications', 'U') IS NOT NULL DROP TABLE Notifications;
CREATE TABLE Notifications (
    Id INT IDENTITY(1,1) PRIMARY KEY,
    UserId INT NOT NULL,
    Message NVARCHAR(255) NOT NULL,
    IsRead BIT DEFAULT 0,
    CreatedAt DATETIME DEFAULT GETDATE()
);
GO

-- Thêm khóa ngoại
ALTER TABLE Posts ADD CONSTRAINT FK_Posts_Author FOREIGN KEY (AuthorId) REFERENCES Users(Id) ON DELETE NO ACTION;
ALTER TABLE Comments ADD CONSTRAINT FK_Comments_Post FOREIGN KEY (PostId) REFERENCES Posts(Id) ON DELETE CASCADE;
ALTER TABLE Comments ADD CONSTRAINT FK_Comments_User FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE SET NULL;
ALTER TABLE Likes ADD CONSTRAINT FK_Likes_Post FOREIGN KEY (PostId) REFERENCES Posts(Id) ON DELETE CASCADE;
ALTER TABLE Likes ADD CONSTRAINT FK_Likes_User FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE SET NULL;
ALTER TABLE Reports ADD CONSTRAINT FK_Reports_Comment FOREIGN KEY (CommentId) REFERENCES Comments(Id) ON DELETE CASCADE;
ALTER TABLE Reports ADD CONSTRAINT FK_Reports_User FOREIGN KEY (ReportedBy) REFERENCES Users(Id) ON DELETE SET NULL;
ALTER TABLE FavoritePosts ADD CONSTRAINT FK_FavoritePosts_User FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE NO ACTION;
ALTER TABLE FavoritePosts ADD CONSTRAINT FK_FavoritePosts_Post FOREIGN KEY (PostId) REFERENCES Posts(Id) ON DELETE NO ACTION;
ALTER TABLE Notifications ADD CONSTRAINT FK_Notifications_User FOREIGN KEY (UserId) REFERENCES Users(Id) ON DELETE CASCADE;
GO
