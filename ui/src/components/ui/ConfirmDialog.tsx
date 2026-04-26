import { AlertTriangle } from "lucide-react";
import { Modal } from "./Modal";

interface ConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: "danger" | "warning";
  isLoading?: boolean;
}

export function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmLabel = "Confirmar",
  cancelLabel = "Cancelar",
  variant = "danger",
  isLoading = false,
}: ConfirmDialogProps) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title} size="sm">
      <div className="flex flex-col gap-5">
        <div className="flex items-start gap-4">
          <div
            className={
              variant === "danger"
                ? "p-2 rounded-lg bg-threat-critical/20"
                : "p-2 rounded-lg bg-threat-medium/20"
            }
          >
            <AlertTriangle
              size={20}
              className={
                variant === "danger" ? "text-threat-critical" : "text-threat-medium"
              }
            />
          </div>
          <p className="text-gray-300 text-sm leading-relaxed">{message}</p>
        </div>
        <div className="flex justify-end gap-3">
          <button onClick={onClose} className="btn-ghost" disabled={isLoading}>
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className={variant === "danger" ? "btn-danger" : "btn-primary"}
          >
            {isLoading ? "Procesando..." : confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  );
}
