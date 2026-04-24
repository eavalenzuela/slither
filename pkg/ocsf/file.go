package ocsf

import "fmt"

// FileSystemActivity (OCSF class_uid 1001).
type FileSystemActivity struct {
	Metadata    Metadata             `json:"metadata"`
	ClassUID    ClassID              `json:"class_uid"`
	ClassName   string               `json:"class_name"`
	ActivityID  FileSystemActivityID `json:"activity_id"`
	TypeUID     uint64               `json:"type_uid"`
	Severity    Severity             `json:"severity_id"`
	SeverityStr string               `json:"severity,omitempty"`
	Time        TimeOCSF             `json:"time"`
	Device      Device               `json:"device"`
	Actor       Actor                `json:"actor"`
	File        File                 `json:"file"`

	// Populated for rename-style operations (activity_id 6).
	RenameTo *File `json:"file_diff,omitempty"`
}

type FileSystemActivityID uint8

const (
	FileActivityUnknown  FileSystemActivityID = 0
	FileActivityCreate   FileSystemActivityID = 1
	FileActivityRead     FileSystemActivityID = 2
	FileActivityUpdate   FileSystemActivityID = 3
	FileActivityDelete   FileSystemActivityID = 4
	FileActivitySetAttr  FileSystemActivityID = 5
	FileActivityRename   FileSystemActivityID = 6
	FileActivitySetOwner FileSystemActivityID = 7
	FileActivityEncrypt  FileSystemActivityID = 8
	FileActivityDecrypt  FileSystemActivityID = 9
	FileActivityMount    FileSystemActivityID = 10
	FileActivityUnmount  FileSystemActivityID = 11
	FileActivityOpen     FileSystemActivityID = 12
	FileActivityOther    FileSystemActivityID = 99
)

func (f *FileSystemActivity) ClassID() ClassID { return ClassFileSystemActivity }

func (f *FileSystemActivity) Validate() error {
	if f.ClassUID != ClassFileSystemActivity {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, f.ClassUID, ClassFileSystemActivity)
	}
	if f.ActivityID == FileActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if f.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if f.File.Path == "" && f.File.Name == "" {
		return fmt.Errorf("%w: file.path or file.name required", ErrInvalidEvent)
	}
	if f.ActivityID == FileActivityRename && f.RenameTo == nil {
		return fmt.Errorf("%w: rename requires file_diff target", ErrInvalidEvent)
	}
	return nil
}
