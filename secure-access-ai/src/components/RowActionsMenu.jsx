import { MoreHorizontal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import "./RowActionsMenu.css";

export default function RowActionsMenu({
  label,
  onEdit,
  onDelete,
  canDelete = true,
}) {
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState(null);
  const menuRef = useRef(null);
  const triggerRef = useRef(null);
  const popoverRef = useRef(null);

  useEffect(() => {
    if (!open) {
      return undefined;
    }

    function closeOnOutsideClick(event) {
      if (
        !menuRef.current?.contains(event.target) &&
        !popoverRef.current?.contains(event.target)
      ) {
        setOpen(false);
      }
    }

    function closeOnEscape(event) {
      if (event.key === "Escape") {
        setOpen(false);
      }
    }

    function closeOnViewportChange() {
      setOpen(false);
    }

    document.addEventListener("pointerdown", closeOnOutsideClick);
    document.addEventListener("keydown", closeOnEscape);
    window.addEventListener("resize", closeOnViewportChange);
    window.addEventListener("scroll", closeOnViewportChange, true);
    return () => {
      document.removeEventListener("pointerdown", closeOnOutsideClick);
      document.removeEventListener("keydown", closeOnEscape);
      window.removeEventListener("resize", closeOnViewportChange);
      window.removeEventListener("scroll", closeOnViewportChange, true);
    };
  }, [open]);

  function runAction(action) {
    setOpen(false);
    action();
  }

  function toggleMenu() {
    if (open) {
      setOpen(false);
      return;
    }
    const rect = triggerRef.current.getBoundingClientRect();
    const menuWidth = 128;
    const menuHeight = canDelete ? 82 : 44;
    setPosition({
      top: Math.max(8, Math.min(rect.bottom + 4, window.innerHeight - menuHeight - 8)),
      left: Math.max(8, Math.min(rect.right - menuWidth, window.innerWidth - menuWidth - 8)),
    });
    setOpen(true);
  }

  return (
    <div className="row-actions-menu" ref={menuRef}>
      <button
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label={`Actions for ${label}`}
        className="row-actions-trigger"
        onClick={toggleMenu}
        ref={triggerRef}
        type="button"
      >
        <MoreHorizontal aria-hidden="true" size={18} />
      </button>
      {open && position && createPortal(
        <div
          className="row-actions-popover"
          ref={popoverRef}
          role="menu"
          style={{ top: position.top, left: position.left }}
        >
          <button onClick={() => runAction(onEdit)} role="menuitem" type="button">
            Edit
          </button>
          {canDelete && (
            <button
              className="danger"
              onClick={() => runAction(onDelete)}
              role="menuitem"
              type="button"
            >
              Delete
            </button>
          )}
        </div>,
        document.body,
      )}
    </div>
  );
}
